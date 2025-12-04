import os
import pandas as pd
import json
import ast
from parsers import *
import argparse

Project_Root = "/home/nkamg/SASTcomparison/"
Experiment_Root = Project_Root + "Synthetic_experiment/"
Synthetic_dataset_path = Project_Root + "SyntheticDataset/"
CWEMapping_Root= Project_Root + "CWEMapping/"

GroundTruthPath = Project_Root + "SyntheticGroundTruth.json"
Ori_Ground_Truth_path = Project_Root + "SyntheticDataset-2025-6-25.csv"


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
    
    df = pd.read_csv(Ori_Ground_Truth_path)
    
    for index, row in df.iterrows():
        case_name = row['TestCase']
        location = row['Vul Position']
        cwe = row['CWE Type']
        groundTruth[case_name] = {
            "cwe": str(cwe),
            "location": location
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
    
    args = parser.parse_args()
    
    sast = args.sast
    mode = args.mode

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
    
    report_dir = Experiment_Root + sast
    mapping_file = CWEMapping_Root + sast + ".txt"
    
    if mode == "collect":
        #sast_all_rep = ALLReports_Root_Dir + sast + '.txt'
        parser.collect(report_dir, mapping_file)
        return
    
    if mode == "evaluate":
        cwe_mapping = getCWEMapping(mapping_file)
        ground_truth = getGroundTruth(GroundTruthPath)
        parser.evaluate(report_dir, ground_truth, cwe_mapping, Synthetic_dataset_path)
        return




if __name__ == "__main__":
    main()