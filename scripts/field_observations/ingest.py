"""HQ poller: validate the station feed and stage metadata for the existing publisher."""
import argparse
import fcntl
import hashlib
import json
import subprocess
import shlex
import time
from pathlib import Path
from .common import SCHEMA, FEED_SCHEMA, EVENT, STATION, HASH, encode, digest, identifier, atomic, safe_file

# Reject unrecognized fields at every level; public exports cannot grow private
# metadata accidentally when station schemas change.
FIELDS = {
 'record': 'schema id station_id capture_event_id status reason human_classification review_scope recordings annotations archive_bundles location ce5_playback recording_window_start_epoch recording_window_end_epoch original_prediction camera_pointing',
 'recording': 'id source_family_id capture_kind started_epoch stopped_epoch video_fps',
 'annotation': 'id classification reviewed_epoch bounds_pixels crop_sha256 frame_references',
 'pointing': 'azimuth_deg elevation_deg settings_epoch detected_epoch',
 'reference': 'recording_id original_frame_index',
 'bundle': 'recording_id identifier url review_revision verified_epoch assets',
 'asset': 'name sha256 bytes url',
 'location': 'status precision county state country',
 'ce5': 'state observed_overlap_seconds',
 'prediction': 'model_sha256 scope classification score',
}

def fields(value, kind):
    if not isinstance(value, dict) or set(value)-set(FIELDS[kind].split()):
        raise ValueError('Unrecognized public '+kind+' fields')

def validate(record, station):
    fields(record,'record')
    event=identifier(record.get('capture_event_id'),EVENT)
    if record.get('schema')!=SCHEMA or record.get('station_id')!=station or record.get('id')!=f'field:{station}:{event}':
        raise ValueError('Observation identity mismatch')
    if record.get('status') not in ('published','withdrawn','pending_evidence'):raise ValueError('Invalid status')
    for r in record.get('recordings',[]):fields(r,'recording')
    for a in record.get('annotations',[]):
        fields(a,'annotation');identifier(a.get('id'),EVENT)
        for ref in a.get('frame_references',[]):fields(ref,'reference')
    for b in record.get('archive_bundles',[]):
        fields(b,'bundle')
        if b.get('url')!='https://archive.org/details/'+b.get('identifier',''):raise ValueError('Invalid archive URL')
        for a in b.get('assets',[]):
            fields(a,'asset');identifier(a.get('sha256'),HASH)
            safe_file(Path('/unused'),a.get('name',''))
            if not a.get('url','').startswith('https://archive.org/download/'+b['identifier']+'/'):raise ValueError('Invalid asset URL')
    for key,kind in [('location','location'),('ce5_playback','ce5'),('original_prediction','prediction')]:
        if key in record:fields(record[key],kind)
    if 'camera_pointing' in record:
        pose=record['camera_pointing'];fields(pose,'pointing')
        if not all(type(pose.get(k)) in (int,float) for k in FIELDS['pointing'].split()) or not (0<=pose['azimuth_deg']<360 and -90<=pose['elevation_deg']<=90 and 0<pose['settings_epoch']<=pose['detected_epoch']):raise ValueError('Invalid capture pointing')
    if record.get('status')=='published':
        if record.get('human_classification')!='anomalous' or not record.get('annotations') or not record.get('archive_bundles'):raise ValueError('Missing reviewed evidence')
        if record.get('location',{}).get('precision')!='county':raise ValueError('Invalid location precision')
    encode(record) # rejects NaN/Infinity
    return event


def stage_page(config, state, page):
    station=identifier(config['station_id'],STATION)
    if page.get('schema')!=FEED_SCHEMA or page.get('station_id')!=station:raise ValueError('Feed identity mismatch')
    epoch=identifier(page.get('source_epoch'),EVENT)
    if state.get('source_epoch') and state['source_epoch']!=epoch:raise ValueError('Station journal changed; explicit reconciliation required')
    cursor=state.get('cursor',0);updates=[]
    for item in page['records']:
        if type(item['sequence']) is not int or item['sequence']!=cursor+1:raise ValueError('Non-contiguous feed')
        record=item['record'];event=validate(record,station)
        if digest(record)!=item['sha256']:raise ValueError('Observation checksum mismatch')
        cursor=item['sequence']
        value=dict(record,revision=cursor,source_epoch=epoch)
        updates.append((f'Field-Station/{station}/{event}.json',encode(value)))
    if cursor!=page['cursor'] or type(page['head']) is not int or page['head']<cursor or page['has_more']!=(cursor<page['head']):raise ValueError('Invalid feed cursor')
    # No destructive mirror: source outages never cause deletion. Tombstones are
    # regular revisioned records and remain available to downstream consumers.
    with open(config['transcripts_lock'],'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        for relative,raw in dict(updates).items():
            atomic(safe_file(config['source_root'],relative),raw)
            outputs=[{'path':relative,'sha256':hashlib.sha256(raw).hexdigest()}]
            completion={'schema':'field-observation-publish/v1','station_id':station,'source_epoch':epoch,'cursor':cursor,'outputs':outputs}
            name='field-station-'+digest(completion)+'.json'
            atomic(safe_file(config['completion_root'],name),completion)
        next_state={'source_epoch':epoch,'cursor':cursor,'last_success_epoch':time.time()}
        atomic(Path(config['state_dir'])/'cursor.json',next_state)
    return next_state


def run(config):
    # Never recreate mount directories on the internal disk during disconnects.
    for mount in config['required_mounts']:
        if not Path(mount).is_mount():raise ValueError('Required external volume unavailable: '+mount)
    state_dir=Path(config['state_dir']);state_dir.mkdir(parents=True,exist_ok=True)
    with open(state_dir/'worker.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        p=state_dir/'cursor.json';state=json.loads(p.read_text()) if p.exists() else {}
        first=True
        for _ in range(100):
            arguments=['--since',str(state.get('cursor',0))]
            if not first:arguments+=['--no-refresh']
            command=config['ssh_command']+[shlex.join(config['remote_command']+arguments)]
            result=subprocess.run(command,capture_output=True,timeout=180,check=True)
            if len(result.stdout)>10*1024*1024:raise ValueError('Feed exceeds transfer limit')
            page=json.loads(result.stdout)
            state=stage_page(config,state,page);first=False
            if not page['has_more']:break
        atomic(state_dir/'status.json',dict(state,status='healthy'))
        return state


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--config',required=True)
    config=json.loads(Path(parser.parse_args().config).read_text())
    try:print(json.dumps(run(config)))
    except Exception as exc:
        # Do not log transport output or credentials.
        if Path(config['state_dir']).is_dir():atomic(Path(config['state_dir'])/'status.json',{'status':'retrying','error_type':type(exc).__name__,'checked_epoch':time.time()})
        raise

if __name__=='__main__':main()
