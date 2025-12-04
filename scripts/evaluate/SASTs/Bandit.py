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

class Bandit(SASTWithDocker):
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
            image="bandit:latest"
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
                cmd='''/bin/bash -c "source ~/.venvs/bandit/bin/activate; bandit -r /target -f json -o /result.json"'''
            )

            end_time = time.time()
            
            # download result from docker container
            self.get(self.container.id, "/result.json", output)
            
            # remove container
            self.container.stop()
            
            return end_time - start_time
        
        except:
            
            return -1
    
    
    def test_dir(self, target, output, db, with_dependency):
        pass
        # # copy target dir
        # self.put
        
        
        # # with_dependency?
        # dependency_selector = ""
        # build_mode = ""
        # if with_dependency == True:
        #     scenario_selector = "source ~/.venvs/tmp/bin/activate; "
        #     # create virtual env
        #     self.container.exec_run(
        #         cmd='''/bin/bash -c "python3.10 -m venv ~/.venvs/tmp"''',
        #         tty=True
        #     )
        #     # install dependencies
        #     self.container.exec_run(
        #         workdir="/workdir/CVECollection/"+ cve_num + "/" + dir_name + "/",
        #         cmd='''/bin/bash -c "source ~/.venvs/%s/bin/activate; pip install -r ./requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple; deactivate"'''%(cve_num),
        #         tty=True
        #     )
        # else:
        #     # rename "requirements.txt" to avoid auto-install
        #     build_mode = "--build-mode=none "
        #     if os.path.exists(CVE_Root_Dir + cve_num + "/" + dir_name + "/requirements.txt"):
        #         os.rename(CVE_Root_Dir + cve_num + "/" + dir_name + "/requirements.txt",
        #                   CVE_Root_Dir + cve_num + "/" + dir_name + "/repquirements.txt"
        #         )
            
        
        # #cmd = "docker exec " + docker_id + " codeql database create -l python -s " + source_dir + " -- " + database_dir
        # start_time = time.time()
        # self.container.exec_run(
        #     cmd='''/bin/bash -c "%scodeql database create %s--threads=0 -l python -s %s -- %s"'''%(scenario_selector, build_mode, source_dir, database_dir),
        #     tty=True
        # )
                
        # # step2: test
        # #cmd = "docker exec " + docker_id + " codeql database run-queries -- " + database_dir + " /codeql/python/ql/src/Security/"
        # self.container.exec_run(
        #     #cmd="codeql database run-queries -- " + database_dir + " /codeql/python/ql/src/Security/",
        #     cmd='''/bin/bash -c "%scodeql database analyze --threads=0 --format=csv --output=%s %s path:/codeql/python/ql/src/codeql-suites/python-security-experimental.qls"'''%(scenario_selector, res, database_dir),
        #     tty=True
        # )
        
        # end_time = time.time()
        
        # if scenario == "WD":
        #     # remove virtual env
        #     self.container.exec_run(
        #         cmd='''/bin/bash -c "rm -rf ~/.venvs/%s"'''%(cve_num),
        #         tty=True
        #     )
        # else:
        #     # restore file name 
        #     if os.path.exists(CVE_Root_Dir + cve_num + "/" + dir_name + "/repquirements.txt"):
        #         os.rename(CVE_Root_Dir + cve_num + "/" + dir_name + "/repquirements.txt",
        #                   CVE_Root_Dir + cve_num + "/" + dir_name + "/requirements.txt"
        #         )
        
        # return end_time - start_time
    
    