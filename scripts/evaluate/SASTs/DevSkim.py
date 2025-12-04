from .SASTBase import SASTWithDocker
import time
import docker
import os
import _thread

def container_timeout(container_id, timeout = 3600):
    time.sleep(timeout)
    try:
        container = client.containers.get(container_id)
        container.stop()
    except:
        return

class DevSkim(SASTWithDocker):
    def __init__(self):
        super().__init__()
            
    def __call__(self, target, output, with_dependency=False):
        
        # have been tested?
        if os.path.exists(output):
            #already tested
            return 0
        
        global client
        client = docker.from_env()
        
        self.container = client.containers.run(
            detach=True,
            tty=True,
            mem_limit="60g",
            auto_remove=True,
            image="devskim:latest"
        )
        
        if os.path.isfile(target):
            return self.test_file(target, output)
        elif os.path.isdir(target):
            return self.test_dir(target, output, with_dependency)


    def test_file(self, target, output):
        
        # create target folder
        self.container.exec_run(
                workdir="/",
                cmd='''/bin/bash -c "mkdir /target"''',
                tty=True
            )
        
        # copy target file
        self.put(self.container.id, target, "/target/")

        try:
            start_time = time.time()

            _thread.start_new_thread(container_timeout, (self.container.id, 3600))
            self.container.exec_run(
                tty=True,
                cmd='''/bin/bash -c "/DevSkim/devskim analyze --source-code /target > /result.json"'''
            )

            end_time = time.time()
            
            # download result from docker container
            self.get(self.container.id, "/result.json", output)
            
            # remove container
            self.container.stop()
            
            return end_time - start_time
        
        except:
            
            return -1
    
    
    def test_dir(self, target, output, with_dependency):
        
        # copy target file
        self.put(self.container.id, target, "/target/")

        try:
            
            dep_selector = ""
            if with_dependency:
                self.container.exec_run(
                    workdir="/target",
                    tty=True,
                    cmd='''/bin/bash -c "python -m venv ~/.venvs/tmp; source ~/.venvs/tmp/bin/activate; pip install -r ./requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple; deactivate"'''
                )
                dep_selector = "source ~/.venvs/tmp/bin/activate; "
            
            start_time = time.time()

            _thread.start_new_thread(container_timeout, (self.container.id, 3600))
            self.container.exec_run(
                tty=True,
                cmd='''/bin/bash -c "%s/DevSkim/devskim analyze --source-code /target > /result.json"'''%(dep_selector)
            )

            end_time = time.time()
            
            # download result from docker container
            self.get(self.container.id, "/result.json", output)
            
            # remove container
            self.container.stop()
            
            return end_time - start_time
        
        except:
            
            return -1
    
    