#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import plistlib
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('agent', Path(__file__).with_name('prepare-hoen-mac-host-agent.py'))
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

class PrepareHostAgentTest(unittest.TestCase):
    def test_configuration_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / 'HoenRemoteDev.app'
            (app / 'Contents/MacOS').mkdir(parents=True)
            with (app / 'Contents/Info.plist').open('wb') as f:
                plistlib.dump({'CFBundleIdentifier': agent.BUNDLE_ID, 'CFBundleExecutable': 'HoenRemoteDev'}, f)
            (app / 'Contents/MacOS/HoenRemoteDev').touch()
            config = agent.agent_for(app)
            self.assertEqual(config['ProgramArguments'], [str(app.resolve() / 'Contents/MacOS/HoenRemoteDev'), '--server'])
            self.assertTrue(config['RunAtLoad'])
            self.assertTrue(config['KeepAlive'])
            self.assertEqual(config['LimitLoadToSessionType'], 'Aqua')
            output = root / 'host.plist'
            agent.write_new(output, config)
            with self.assertRaises(FileExistsError):
                agent.write_new(output, {})
            with output.open('rb') as f:
                self.assertEqual(plistlib.load(f), config)
            with (app / 'Contents/Info.plist').open('wb') as f:
                plistlib.dump({'CFBundleIdentifier': 'wrong', 'CFBundleExecutable': 'HoenRemoteDev'}, f)
            with self.assertRaises(ValueError):
                agent.agent_for(app)

if __name__ == '__main__':
    unittest.main()
