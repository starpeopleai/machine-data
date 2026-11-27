import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from field_observations.common import encode,digest,atomic
from field_observations.export import journal,refresh,feed,observation
from field_observations.ingest import stage_page,validate

class Observations(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.station='test-station';self.event='a'*32;self.sid='20261112T130346Z-d036dc'
        self.review={'sample_id':self.event,'event_id':self.event,'label':'anomalous','human_confirmed':True,'bounds':[1,2,64,64],'reviewed_epoch':9000,'native_crop_sha256':'b'*64}
        self.group={'kind':'alert_web','id':self.event,'annotations':[self.review]}
        self.revision=hashlib.sha256(json.dumps([self.group],sort_keys=True).encode()).hexdigest()
        self.write('uap-lab/archive-review-groups.json',{'groups':{self.sid:[self.group]}})
        self.write('uap-lab/email-reviews/training-manifest.json',{})
        self.write_review()
        self.write('notifications/outbox/'+self.event+'/event.json',{'created_epoch':8000,'model':'c'*64,'classification':'not_anomalous','score':.2})
        ann={'review_revision':self.revision,'annotations':[{'review_id':self.event,'annotation_id':self.event,'frame':10,'bounds':[1,2,64,64],'label':'anomalous'}]}
        self.write('sessions/'+self.sid+'/review-annotations.json',ann)
        self.manifest={'started_epoch':1000,'stopped_epoch':1060,'video_fps':59.94,'internet_archive':{'state':'retaining','verified_at':10000,'identifier':'test-archive','files':[{'name':'review-annotations.json','sha256':digest(ann),'bytes':len(encode(ann))},{'name':'video.mp4','sha256':'d'*64,'bytes':1234,'private_source':'/private/secret'}]}}
        self.write('sessions/'+self.sid+'/manifest.json',self.manifest)
        self.write('sessions/'+self.sid+'/archive-decision.json',{'review_revision':self.revision,'bundle_ready':True,'human_confirmed':True,'confirmed_anomalous':True})
        self.db=journal(self.root/'state.sqlite',self.station);self.addCleanup(self.db.close)
        self.config={'station_id':self.station,'source_root':str(self.root/'source'),'completion_root':str(self.root/'completed'),'state_dir':str(self.root/'hq'),'transcripts_lock':str(self.root/'lock')}
    def write(self,path,value):atomic(self.root/path,value)
    def write_review(self):self.write('uap-lab/email-reviews/examples/'+self.event+'/review.json',self.review)
    def test_capture_time_prediction_privacy_and_idempotency(self):
        self.assertEqual(refresh(self.root,self.station,self.db),1)
        record=feed(self.db,self.station)['records'][0]['record']
        self.assertEqual(record['recording_window_start_epoch'],1000)
        self.assertEqual(record['annotations'][0]['reviewed_epoch'],9000)
        self.assertEqual(record['original_prediction']['classification'],'not_anomalous')
        self.assertNotIn('private_source',json.dumps(record))
        self.assertEqual(record['ce5_playback']['state'],'unknown')
        self.assertEqual(refresh(self.root,self.station,self.db),0)
    def test_pointing_is_bound_to_capture_and_remains_stable(self):
        self.write('notifications/outbox/'+self.event+'/event.json', {'detected_epoch': 1000})
        pose = {'updated_epoch': 1001, 'camera_azimuth_deg': 0, 'camera_elevation_deg': -5}
        self.write('air-traffic/settings.json', pose)
        refresh(self.root, self.station, self.db)
        first = feed(self.db, self.station)['records'][-1]['record']
        self.assertNotIn('camera_pointing', first)
        pose['updated_epoch'] = 999
        self.write('notifications/outbox/'+self.event+'/camera-pointing.json', pose)
        refresh(self.root, self.station, self.db)
        record = feed(self.db, self.station)['records'][-1]['record']
        validate(record, self.station)
        self.assertEqual(record['camera_pointing'], {'azimuth_deg':0, 'elevation_deg':-5, 'settings_epoch':999, 'detected_epoch':1000})
        self.assertEqual(refresh(self.root, self.station, self.db), 0)

    def test_negative_review_withdraws(self):
        refresh(self.root,self.station,self.db)
        self.review['label']='not_anomalous';self.write_review()
        refresh(self.root,self.station,self.db)
        self.assertEqual(feed(self.db,self.station,1)['records'][0]['record']['status'],'withdrawn')
    def test_changed_bounds_suspend_old_evidence(self):
        refresh(self.root,self.station,self.db)
        self.review['bounds']=[10,20,128,128];self.write_review()
        refresh(self.root,self.station,self.db)
        self.assertEqual(feed(self.db,self.station,1)['records'][0]['record']['status'],'pending_evidence')
    def test_missing_volume_is_not_mass_deletion(self):
        refresh(self.root,self.station,self.db)
        (self.root/'uap-lab/archive-review-groups.json').unlink()
        with self.assertRaises(FileNotFoundError):refresh(self.root,self.station,self.db)
        self.assertEqual(feed(self.db,self.station)['head'],1)
    def test_bad_receipt_not_published(self):
        self.manifest['internet_archive']['files'][0]['sha256']='e'*64
        self.write('sessions/'+self.sid+'/manifest.json',self.manifest)
        self.assertEqual(refresh(self.root,self.station,self.db),0)
    def test_publication_commit_and_replay(self):
        refresh(self.root,self.station,self.db);page=feed(self.db,self.station)
        state=stage_page(self.config,{},page)
        self.assertEqual(state['cursor'],1)
        self.assertEqual(len(list((self.root/'completed').glob('*.json'))),1)
        stage_page(self.config,{},page) # crash after files, before caller acknowledges
        self.assertEqual(len(list((self.root/'completed').glob('*.json'))),1)
        self.assertTrue((self.root/'source/Field-Station'/self.station/(self.event+'.json')).is_file())
    def test_checksums_sequence_epoch_and_private_fields_rejected(self):
        refresh(self.root,self.station,self.db);page=feed(self.db,self.station)
        bad=copy.deepcopy(page);bad['records'][0]['sha256']='f'*64
        with self.assertRaises(ValueError):stage_page(self.config,{},bad)
        with self.assertRaises(ValueError):stage_page(self.config,{'source_epoch':'f'*32},page)
        bad=copy.deepcopy(page);bad['records'][0]['sequence']=2
        with self.assertRaises(ValueError):stage_page(self.config,{},bad)
        record=copy.deepcopy(page['records'][0]['record']);record['location']['latitude']=37
        with self.assertRaises(ValueError):validate(record,self.station)
    def test_failed_completion_does_not_advance_cursor(self):
        refresh(self.root,self.station,self.db);page=feed(self.db,self.station)
        original=atomic
        def fail_completion(path,value):
            if 'completed' in str(path):raise OSError('disk full')
            return original(path,value)
        with patch('field_observations.ingest.atomic',side_effect=fail_completion):
            with self.assertRaises(OSError):stage_page(self.config,{},page)
        self.assertFalse((self.root/'hq/cursor.json').exists())
        self.assertEqual(stage_page(self.config,{},page)['cursor'],1)

if __name__=='__main__':unittest.main()
