import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from SASTs.Codeql import Codeql
from SASTs.Pysa import Pysa
from SASTs.Semgrep import Semgrep
from SASTs.Bandit import Bandit
from SASTs.Snyk import Snyk
from SASTs.Bearer import Bearer
from SASTs.DevSkim import DevSkim
from SASTs.Dlint import Dlint

import time
import argparse
import zipfile

log = ""

Project_Root = "/home/nkamg/SASTcomparison/"
Realworld_dataset_path = Project_Root + "CVECollection/"
Experiment_Root = Project_Root + "Realworld_experiment/"
CVE_List_path = Project_Root + "CVE_GT.txt"

def Log(message:str):
    current_time = time.asctime(time.localtime(time.time()))
    
    message = current_time + " " + message + "\n"
    
    log.write(message)
    log.flush()
    
def un_zip(file_name:str):
    #file_name: absolute path of zip
    dir_name = file_name.split(".zip")[0]
    parent_dir = os.path.abspath(os.path.join(dir_name, "../"))
    if os.path.isdir(dir_name):
        #print(file_name)
        Log(file_name + " Already unzipped")
        return dir_name
    
    zip_file = zipfile.ZipFile(file_name)
    ori_name = zip_file.namelist()[0]
    zip_file.extractall(os.path.abspath(os.path.join(dir_name,"../")))
    os.rename(os.path.abspath(os.path.join(parent_dir, ori_name)), dir_name)
    zip_file.close()
    
    Log(file_name + " Unzipped")
    return dir_name

def prepare_outpath(sast, target, with_dependency):
    
    CVE = target[0]
    dir_name = target[1]
    wd = "WD" if with_dependency else "ND"
    fix_or_vul = "_vul" if dir_name.endswith("-vul") else "_fix"
    
    out_dir = Experiment_Root + sast + "/" + wd + "/"
    
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    
    output = ""
    if sast == "Codeql":
        output = out_dir + CVE + fix_or_vul + ".csv"
    elif sast == "Pysa":
        output = out_dir + CVE + fix_or_vul
    elif sast == "Semgrep":
        output = out_dir + CVE + fix_or_vul + ".json"
    elif sast == "Bandit":
        output = out_dir + CVE + fix_or_vul + ".json"
    elif sast == "Snyk":
        output = out_dir + CVE + fix_or_vul + ".json"
    elif sast == "Bearer":
        output = out_dir + CVE + fix_or_vul + ".json"
    elif sast == "DevSkim":
        output = out_dir + CVE + fix_or_vul + ".json"
    elif sast == "Dlint":
        output = out_dir + CVE + fix_or_vul + ".txt"
    
    return output


def do_test(sast:str, targets, with_dependency:bool):
    
    ltime = []
    
    test_func = ""
    if sast == "Codeql":
        test_func = Codeql()
    elif sast == "Pysa":
        config = Project_Root + "scripts/auto_pysa.tcl"
        test_func = Pysa(config)
    elif sast == "Semgrep":
        test_func = Semgrep()
    elif sast == "Bandit":
        test_func = Bandit()
    elif sast == "Snyk":
        test_func = Snyk()
    elif sast == "Bearer":
        test_func = Bearer()
    elif sast == "DevSkim":
        test_func = DevSkim()
    elif sast == "Dlint":
        test_func = Dlint()
    

    left = len(targets)
    # [CVE_NUM, DIR_NAME]
    for target in targets:
        left -= 1
        Log("TESTING " + target[0] + ", " + str(left) + " targets left")

        output = prepare_outpath(sast, target, with_dependency)

        target_dir = Realworld_dataset_path + target[0] + "/" + target[1]
        total_time = test_func(target_dir, output)
        
        if total_time == None:
            print("None time")

        if total_time == 0:
            Log("Already tested, skipped")

        if total_time == -1:
            Log("An error raised, skipped")
            ltime.append(0)
            continue

        ltime.append(total_time)
        Log("TESTED " + target[0] + ", " + str(total_time) + " seconds taken, " + str(left) + " targets left")
    
    tmp = 0
    for i in ltime:
        tmp += i
    Log("Took " + str(tmp) + " seconds to test")



if __name__=='__main__':
    
    parser = argparse.ArgumentParser(description="Evaluate SAST with Real-world Dataset!")
    parser.add_argument("sast", type=str, help="SAST to evaluate. Codeql, Pysa, Bandit, Semgrep, Snyk, Bearer, DevSkim are available.")
    parser.add_argument("--with_dependency", action="store_true", help="Whether to test with dependency or not. Default is False.")
    
    args = parser.parse_args()
    
    sast = args.sast
    with_dependency = args.with_dependency
    
    now = time.asctime(time.localtime(time.time()))
    logfile = "/home/nkamg/SASTcomparison/scripts/evaluate/Realworld/logs/log_realworld_"+sast+"_"+now
    log = open(logfile, "w")
    
    f = open(CVE_List_path, 'r')
    CVE_List = f.read().split("\n")
    f.close()
    
    targets = []
    for i in CVE_List:
        CVE_Dir = os.path.join(Realworld_dataset_path, i)
        files = os.listdir(CVE_Dir)  # file name, not abs path
        for file in files:
            if file.endswith("-vul.zip") or file.endswith("-fix.zip"):
                file_name = os.path.join(CVE_Dir, file)
                dir_name = un_zip(file_name)  # unzipped dir
                targets.append([i, file[:-4]]) # [CVE_NUM, DIR_NAME]

    print(targets)
    
    do_test(sast, targets, with_dependency)

    log.close()