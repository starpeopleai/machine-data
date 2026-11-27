"""Read-only station adapter plus a durable public-metadata change journal.

Runs over authenticated SSH, never through the public/onion web application.
Only current human-confirmed anomalies with revision-matched Archive receipts
are first published. Changes remain journaled on the field SSD during outages.
"""
import argparse
import collections
import fcntl
import hashlib
import json
import sqlite3
import time
import uuid
from contextlib import closing
from pathlib import Path
from urllib.parse import quote
from .common import (SCHEMA, FEED_SCHEMA, STATION, EVENT, SESSION, HASH, IDENTIFIER,
                     MAX_RECORD_BYTES, encode, digest, read_json, safe_file, number, identifier)


def source_file(root, relative):
    prefix='uap-lab/email-reviews/'
    if relative.startswith(prefix):
        base=Path(root)/'uap-lab/email-reviews'
        if base.is_symlink():
            resolved=base.resolve()
            if not ((resolved == Path(root)/'review-training-staging' and Path(root).is_mount()) or (resolved == Path('/Volumes/UFO-SWR/review-training') and Path('/Volumes/UFO-SWR').is_mount())):
                raise ValueError('Expected review training SSD unavailable')
            return safe_file(resolved,relative[len(prefix):])
    return safe_file(root,relative)


def source_json(root, relative, optional=False):
    p=source_file(root,relative)
    return read_json(p.parent,p.name,optional=optional)


def signature(path):
    stat = path.stat()
    return stat.st_mtime_ns, stat.st_size, stat.st_ino


def coarse_location(root, manifest):
    epoch = number(manifest.get('started_epoch'), 1)
    value = manifest.get('observation_location')
    if not isinstance(value, dict) or value.get('status') != 'known':
        value = {}
        p = source_file(root, 'station-location/history.sqlite')
        if p.is_file() and epoch:
            with closing(sqlite3.connect(p.resolve().as_uri()+'?mode=ro', uri=True, timeout=.2)) as db:
                row = db.execute('SELECT sampled_epoch,valid_until,status,county,state,country FROM fixes WHERE sampled_epoch<=? ORDER BY sampled_epoch DESC LIMIT 1', (epoch,)).fetchone()
                if row and row[2] == 'known' and row[0] <= epoch < min(row[1], row[0]+180):
                    value = dict(zip(('county', 'state', 'country'), row[3:]))
    if not all(isinstance(value.get(k), str) and 0 < len(value[k]) <= 120 and not any(ord(c)<32 for c in value[k]) for k in ('county','state','country')):
        return {'status':'unknown','precision':'county'}
    return dict(status='known', precision='county', **{k:value[k] for k in ('county','state','country')})


def ce5_context(root, start, end):
    p = source_file(root, 'audio/playback.sqlite3')
    if not start or not end or end <= start or not p.is_file():
        return {'state':'unknown'}
    with closing(sqlite3.connect(p.resolve().as_uri()+'?mode=ro', uri=True, timeout=.2)) as db:
        intervals = db.execute('SELECT start,end FROM playback WHERE start<? AND end>? AND end>start', (end,start)).fetchall()
        if intervals:
            # Union overlapping playback intervals; do not double-count tracks.
            total=0;cursor=start
            for a,b in sorted(intervals):
                a=max(a,start,cursor);b=min(b,end)
                if b>a:total+=b-a;cursor=b
            return {'state':'on','observed_overlap_seconds':round(total,3)}
        tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if 'coverage' in tables:
            cursor=start
            for a,b in db.execute('SELECT start,end FROM coverage WHERE end>=? AND start<=? ORDER BY start',(start,end)):
                if a>cursor:break
                cursor=max(cursor,b)
            if cursor>=end:return {'state':'off'}
    return {'state':'unknown'}


def current_review(root, annotation, event):
    aid=identifier(annotation.get('sample_id',annotation.get('id',event)), EVENT)
    row=source_json(root,f'uap-lab/email-reviews/examples/{aid}/review.json',optional=True)
    if row is None:raise ValueError('Authoritative review record unavailable')
    if row.get('event_id') != event:raise ValueError('Review/event identity mismatch')
    return row


def receipt_assets(receipt):
    assets={}
    for f in receipt.get('files',[]):
        name=f.get('name','');safe_file(Path('/__unused__'),name)
        if not HASH.fullmatch(str(f.get('sha256',''))) or type(f.get('bytes')) is not int or f['bytes']<0:
            continue
        if name in ('video.mp4','video-annotated.mp4','rf.jsonl','review-annotations.json','frames/reviewed-index.json') or (name.startswith('frames/reviewed-') and name.endswith(('-original.png','-annotated.png'))):
            assets[name]={'name':name,'sha256':f['sha256'],'bytes':f['bytes']}
    return assets


def source_groups(root):
    raw=source_json(root,'uap-lab/archive-review-groups.json')
    if not isinstance(raw,dict) or not isinstance(raw.get('groups'),dict):raise ValueError('Archive group index unavailable')
    result=collections.defaultdict(list)
    for sid,groups in raw['groups'].items():
        identifier(sid,SESSION)
        for group in groups:
            if group.get('kind')!='alert_web':continue
            event=identifier(group.get('id'),EVENT)
            result[event].append((sid,group,groups))
    return result


def prediction(event):
    model=event.get('model')
    if not isinstance(model,str) or not HASH.fullmatch(model):return None
    label=event.get('classification')
    result={'model_sha256':model,'scope':'original_capture_prediction'}
    if label in ('anomalous','not_anomalous'):result['classification']=label
    score=number(event.get('score'))
    if score is not None:result['score']=score
    return result


def observation(root, station, event_id, entries, prior):
    oid=f'field:{station}:{event_id}'
    base={'schema':SCHEMA,'id':oid,'station_id':station,'capture_event_id':event_id}
    previous_ids={a['id'] for a in (prior or {}).get('annotations',[])}
    selected={}
    for _,group,_ in entries:
        for a in group.get('annotations',[]):
            row=current_review(root,a,event_id);selected[row.get('sample_id',event_id)]=row
    # Retain negative/deleted decisions even after the archive group disappears.
    for aid in previous_ids-set(selected):
        selected[aid]=current_review(root,{'sample_id':aid},event_id)
    positive={k:v for k,v in selected.items() if v.get('human_confirmed') is True and not v.get('deleted') and v.get('label')=='anomalous'}
    if not positive:
        return dict(base,status='withdrawn',reason='no_current_human_anomalous_review') if prior else None
    event=source_json(root,f'notifications/outbox/{event_id}/event.json',optional=True) or {}
    bundles=[];annotations={};starts=[];ends=[];locations=[];contexts=[];recordings=[]
    for sid,group,all_groups in entries:
        folder=f'sessions/{sid}'
        manifest=source_json(root,folder+'/manifest.json',optional=True)
        decision=source_json(root,folder+'/archive-decision.json',optional=True)
        if not manifest or not decision:continue
        if manifest.get('archive_withdrawn') or source_file(root,f'manual-deletions/{sid}.json').exists():continue
        receipt=manifest.get('internet_archive',{})
        # This is the existing archive exporter's exact revision calculation.
        expected=hashlib.sha256(json.dumps(all_groups,sort_keys=True).encode()).hexdigest()
        if not(decision.get('bundle_ready') and decision.get('human_confirmed') and decision.get('confirmed_anomalous') and decision.get('review_revision')==expected):continue
        if receipt.get('state') not in ('retaining','cleaned') or not number(receipt.get('verified_at'),1):continue
        archive_id=identifier(receipt.get('identifier'),IDENTIFIER)
        assets=receipt_assets(receipt)
        review_path=source_file(root,folder+'/review-annotations.json')
        if not review_path.is_file():continue
        review_bytes=review_path.read_bytes()
        exported=json.loads(review_bytes)
        if exported.get('review_revision')!=expected or assets.get('review-annotations.json',{}).get('sha256')!=hashlib.sha256(review_bytes).hexdigest():continue
        # Check each archived annotation against its current authoritative review.
        linked=[];stale=False;bundle_annotations={}
        for a in exported.get('annotations',[]):
            if a.get('review_id')!=event_id:continue
            aid=identifier(a.get('annotation_id'),EVENT)
            row=selected.get(aid)
            if not row or row.get('deleted') or row.get('label')!=a.get('label') or row.get('bounds')!=a.get('bounds'):
                stale=True;break
            if aid not in positive:continue
            bounds=a.get('bounds');frame=a.get('frame')
            if not isinstance(bounds,list) or len(bounds)!=4 or any(number(n,0) is None for n in bounds) or min(bounds[2:])<=0 or type(frame) is not int or frame<0:raise ValueError('Invalid reviewed geometry')
            bundle_annotations[aid]={'id':aid,'classification':'anomalous','reviewed_epoch':number(row.get('reviewed_epoch'),1),'bounds_pixels':bounds,'crop_sha256':identifier(row.get('native_crop_sha256'),HASH),'frame_references':[{'recording_id':sid,'original_frame_index':frame}]}
            linked.append(frame)
        if stale:continue
        if not linked:continue
        # Only publish relevant stills and small indices, never local paths/logs.
        selected_assets=[]
        for name,item in assets.items():
            if name.startswith('frames/reviewed-') and not any(f'/frame-{n:09d}-' in name for n in linked):continue
            selected_assets.append(dict(item,url=f'https://archive.org/download/{archive_id}/{quote(name,safe="/")}'))
        if not any(a['name']=='video.mp4' for a in selected_assets):continue
        for aid, annotation in bundle_annotations.items():
            if aid in annotations:
                annotations[aid]['frame_references'].extend(annotation['frame_references'])
            else:annotations[aid]=annotation
        bundles.append({'recording_id':sid,'identifier':archive_id,'url':f'https://archive.org/details/{archive_id}','review_revision':expected,'verified_epoch':receipt['verified_at'],'assets':sorted(selected_assets,key=lambda a:a['name'])})
        start=number(manifest.get('started_epoch'),1);end=number(manifest.get('stopped_epoch'),1)
        if start:starts.append(start)
        if end:ends.append(end)
        locations.append(coarse_location(root,manifest));contexts.append(ce5_context(root,start,end))
        recordings.append({'id':sid,'source_family_id':f'field-recording:{station}:{sid}','capture_kind':'manual' if manifest.get('capture_origin')=='manual' else 'automatic','started_epoch':start,'stopped_epoch':end,'video_fps':number(manifest.get('video_fps'),0)})
    if not bundles:
        return dict(base,status='pending_evidence',reason='current_review_bundle_not_verified',annotations=[{'id':a} for a in sorted(positive)]) if prior else None
    # Keep one canonical event even if multiple recordings contain its frames.
    out=dict(base,status='published',human_classification='anomalous',review_scope='human_reviewed_objects',recordings=sorted(recordings,key=lambda r:r['id']),annotations=sorted(annotations.values(),key=lambda a:a['id']),archive_bundles=sorted(bundles,key=lambda b:b['identifier']),location=locations[0] if locations and all(l==locations[0] for l in locations) else {'status':'unknown','precision':'county'},ce5_playback=contexts[0] if len(contexts)==1 else {'state':'unknown'},recording_window_start_epoch=min(starts) if starts else None,recording_window_end_epoch=max(ends) if ends else None)
    # The station settings revision is valid from its edit timestamp until superseded.
    # Preserve the first contemporaneous pointing attached to this capture.
    pointing = (prior or {}).get('camera_pointing')
    if pointing is None:
        epoch = number(event.get('detected_epoch'), 1)
        pose = source_json(root, f'notifications/outbox/{event_id}/camera-pointing.json', optional=True)
        if not pose:
            pose = source_json(root, 'air-traffic/settings.json', optional=True) or {}
        updated = number(pose.get('updated_epoch'), 1)
        az, el = pose.get('camera_azimuth_deg'), pose.get('camera_elevation_deg')
        if epoch and updated and updated <= epoch and epoch <= time.time() and type(az) in (int,float) and 0 <= az < 360 and type(el) in (int,float) and -90 <= el <= 90:
            pointing = {'azimuth_deg':az, 'elevation_deg':el, 'settings_epoch':updated, 'detected_epoch':epoch}
    if pointing:
        out['camera_pointing'] = pointing
    original=prediction(event) or (prior or {}).get('original_prediction')
    if original:out['original_prediction']=original
    return out


def refresh(root, station, db):
    root=Path(root);identifier(station,STATION)
    # A missing/unmounted source never means that every observation was deleted.
    marker=source_file(root,'uap-lab/email-reviews/training-manifest.json')
    group_path=source_file(root,'uap-lab/archive-review-groups.json')
    before=(signature(marker),signature(group_path))
    groups=source_groups(root)
    previous={r[0]:json.loads(r[1]) for r in db.execute('SELECT event_id,payload FROM current')}
    updates=[]
    for event_id in sorted(set(groups)|set(previous)):
        value=observation(root,station,event_id,groups.get(event_id,[]),previous.get(event_id))
        if value is None:continue
        payload=encode(value)
        if len(payload)>MAX_RECORD_BYTES:raise ValueError('Observation exceeds bounded export size')
        if previous.get(event_id)==value:continue
        updates.append((event_id,payload.decode(),digest(value)))
    if before!=(signature(marker),signature(group_path)):raise ValueError('Reviews changed during export; retry next poll')
    with db:
        for event_id,payload,sha in updates:
            db.execute('INSERT INTO changes(event_id,payload,sha256,created_epoch) VALUES(?,?,?,?)',(event_id,payload,sha,time.time()))
            db.execute('INSERT INTO current(event_id,payload) VALUES(?,?) ON CONFLICT(event_id) DO UPDATE SET payload=excluded.payload',(event_id,payload))
    return len(updates)


def journal(path,station):
    path=Path(path)
    if path.is_symlink():raise ValueError('Unsafe journal path')
    path.parent.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(path,timeout=2)
    db.executescript('CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS current(event_id TEXT PRIMARY KEY,payload TEXT NOT NULL); CREATE TABLE IF NOT EXISTS changes(sequence INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT NOT NULL,payload TEXT NOT NULL,sha256 TEXT NOT NULL,created_epoch REAL NOT NULL);')
    with db:
        db.execute('INSERT OR IGNORE INTO meta VALUES(?,?)',('epoch',uuid.uuid4().hex))
        db.execute('INSERT OR IGNORE INTO meta VALUES(?,?)',('station',station))
    if db.execute('SELECT value FROM meta WHERE key="station"').fetchone()[0]!=station:raise ValueError('Journal station changed')
    return db


def feed(db,station,since=0,limit=25):
    if type(since) is not int or since<0 or not 1<=limit<=100:raise ValueError('Invalid feed cursor or limit')
    head=db.execute('SELECT COALESCE(MAX(sequence),0) FROM changes').fetchone()[0]
    if since>head:raise ValueError('Feed cursor exceeds journal; explicit resync required')
    records=[];size=0;cursor=since
    for seq,payload,sha in db.execute('SELECT sequence,payload,sha256 FROM changes WHERE sequence>? ORDER BY sequence LIMIT ?',(since,limit)):
        if records and size+len(payload)>8*1024*1024:break
        records.append({'sequence':seq,'sha256':sha,'record':json.loads(payload)});cursor=seq;size+=len(payload)
    return {'schema':FEED_SCHEMA,'station_id':station,'source_epoch':db.execute('SELECT value FROM meta WHERE key="epoch"').fetchone()[0],'cursor':cursor,'head':head,'has_more':cursor<head,'records':records}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True);parser.add_argument('--station-id',required=True);parser.add_argument('--journal',type=Path,required=True);parser.add_argument('--since',type=int,default=0);parser.add_argument('--limit',type=int,default=25)
    parser.add_argument('--no-refresh',action='store_true')
    args=parser.parse_args()
    identifier(args.station_id,STATION)
    if not args.root.is_mount():raise ValueError('Source volume is not mounted')
    safe_file(args.root,'uap-lab/archive-review-groups.json').stat()
    args.journal.resolve().relative_to(args.root.resolve())
    args.journal.parent.mkdir(parents=True,exist_ok=True)
    with open(str(args.journal)+'.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with closing(journal(args.journal,args.station_id)) as db:
            if not args.no_refresh:refresh(args.root,args.station_id,db)
            print(encode(feed(db,args.station_id,args.since,args.limit)).decode(),end='')

if __name__=='__main__':main()
