import os
import pandas as pd
import json
import ast
from parsers import *
import argparse

Project_Root = "/home/nkamg/SASTcomparison/"
Experiment_Root = Project_Root + "Realworld_experiment/"
Realworld_dataset_path = Project_Root + "CVECollection/"
CWEMapping_Root= Project_Root + "CWEMapping/"

GroundTruthPath = Project_Root + "GroundTruth.json"
Test_List_path = Project_Root + "CVE_GT.txt"
Ori_Ground_Truth_path = Project_Root + "CVE-Collection-2025-3-23.csv"


def getGroundTruth(GroundTruthPath):
    # does groundTruth.json exist?
    if os.path.exists(GroundTruthPath):
        # read ground truth from json
        with open(GroundTruthPath) as f:
            groundTruth = json.load(f)
            return groundTruth
    
    groundTruth = {}
    # json doesn't exist, generate SyntheticGroundTruth.json with csv    
    # Get Ground Truth  {case_name:{cwe, location}}
    
    test_list = []  # CVE under test
    with open(Test_List_path) as f:
        test_list = f.readlines()
        test_list = [i.strip() for i in test_list]
    
    
    df = pd.read_csv(Ori_Ground_Truth_path)
    
    df = df.loc[df['CVE'].isnull() != True]
    df['CVE'] = df['CVE'].map(lambda x: x[x.find('CVE-'):])
    
    # filter out CVE that is in test_list
    df = df.loc[df['CVE'].isin(test_list)]
    
    for index, row in df.iterrows():
        cve = row['CVE']
        location = row['vul position']
        cwe = row['CWE Type']
        groundTruth[cve] = {
            "location": location.split("; "), 
            "cwe": cwe.split(";")[0]
        }
    
    with open(GroundTruthPath, 'w') as f:
        json.dump(groundTruth, f)
    
    return groundTruth


def getCWEMapping(mapping_file):
    
    cwe_mapping = {}
    
    f = open(mapping_file)
    content = f.readlines()
    for line in content:
        line = line.split(';')
        descript = line[0].strip()
        if len(line) == 1:
            # not cwe in selected categories
            cwe_mapping[descript] = [""]
            continue
        cwe = line[1].strip()
        cwe_mapping[descript] = cwe.split(",")
    f.close()
    return cwe_mapping


def main():
    
    parser = argparse.ArgumentParser(description="Evaluate SAST with Synthetic Dataset!")
    parser.add_argument("sast", type=str, help="SAST to evaluate. Codeql, Pysa, Bandit, Semgrep, Snyk, Bearer, DevSkim are available.")
    parser.add_argument("mode", type=str, help="collect or evaluate")
    parser.add_argument("--with_dependency", action="store_true", help="Whether to test with dependency or not. Default is False.")
    
    args = parser.parse_args()
    
    sast = args.sast
    mode = args.mode
    with_dependency = args.with_dependency

    parser = None
    if sast == 'Codeql':
        parser = Codeql_parser()
        
    if sast == 'Pysa':
        parser = Pysa_parser()
        
    if sast == 'Semgrep':
        parser = Semgrep_parser()
        
    if sast == 'Snyk':
        parser = Snyk_parser()
    
    if sast == 'Bandit':
        parser = Bandit_parser()
        
    if sast == 'DevSkim':
        parser = DevSkim_parser()
    
    if sast == 'Bearer':
        parser = Bearer_parser()
        
    if sast == 'Dlint':
        parser = Dlint_parser()
    
    report_dir = Experiment_Root + sast + "/"
    if with_dependency:
        report_dir += "WD/"
    else:
        report_dir += "ND/"
    mapping_file = CWEMapping_Root + sast + ".txt"
    
    if mode == "collect":
        #sast_all_rep = ALLReports_Root_Dir + sast + '.txt'
        parser.collect(report_dir, mapping_file)
        return
    
    if mode == "evaluate":
        cwe_mapping = getCWEMapping(mapping_file)
        ground_truth = getGroundTruth(GroundTruthPath)
        parser.evaluate(report_dir, ground_truth, cwe_mapping, Realworld_dataset_path)
        return




if __name__ == "__main__":
    main()