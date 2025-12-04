import subprocess

class SASTBase:
    def __init__(self):
        pass
    
    def __call__(self, target, output, with_dependency):
        return 0
    

class SASTWithDocker(SASTBase):
    def __init__(self):
        super().__init__()
    
    def put(self, container_id, source_path, target_path):    
        subprocess.run(['docker', 'cp', source_path, '%s:%s'%(container_id, target_path)])
    
    def get(self, container_id, source_path, target_path):
        subprocess.run(['docker', 'cp', '%s:%s'%(container_id, source_path), target_path])
