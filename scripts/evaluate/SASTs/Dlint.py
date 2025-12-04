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

class Dlint(SASTWithDocker):
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
            image="dlint:latest"
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
                cmd='''/bin/bash -c "source ~/.venvs/dlint/bin/activate; python -m flake8 --select=DUO --color never --output-file /result.txt /target"'''
            )

            end_time = time.time()
            
            # download result from docker container
            self.get(self.container.id, "/result.txt", output)
            
            # remove container
            self.container.stop()
            
            return end_time - start_time
        
        except:
            
            return -1
    
    
    def test_dir(self, target, output, with_dependency):
        # copy target file
        self.put(self.container.id, target, "/target/")

        try:
            
            if with_dependency:
                self.container.exec_run(
                    workdir="/target",
                    tty=True,
                    cmd='''/bin/bash -c "source ~/.venvs/dlint/bin/activate; pip install -r ./requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple; deactivate"'''
                )
           
            
            start_time = time.time()

            _thread.start_new_thread(container_timeout, (self.container.id, 3600))
            self.container.exec_run(
                tty=True,
                cmd='''/bin/bash -c "source ~/.venvs/dlint/bin/activate; python -m flake8 --select=DUO --color never --output-file /result.txt /target"'''
            )

            end_time = time.time()
            
            # download result from docker container
            self.get(self.container.id, "/result.txt", output)
            
            # remove container
            self.container.stop()
            
            return end_time - start_time
        
        except:
            
            return -1
    
    
    