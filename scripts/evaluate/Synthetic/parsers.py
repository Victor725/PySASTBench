import os
import pandas as pd
import ast
import json

def getFunc(file, line_num):
    #print(file)
    #print(line_num)
    
    f = open(file)
    code = f.read()
    Ast = None
    try:
        Ast = ast.parse(code)  # Ast is a instance of ast.Module
    except:
        # Ast = ast.parse(code, feature_version=(2,5))
        return ""
    
    current = Ast
    scope = []
    
    def find_body(node):
        try:
            body = node.body
        except:
            return None
        
        # handle 'except'
        if isinstance(node, ast.Try) == True:
            body += node.handlers
            body += node.orelse
            body += node.finalbody
        
        for n in body:
            if line_num >= n.lineno and line_num <= n.end_lineno: # line_num lie in the node
                if isinstance(n, ast.ClassDef) or isinstance(n, ast.FunctionDef) or isinstance(n, ast.AsyncFunctionDef):
                    # fine body that contains line_num
                    scope.append(n.name)
                return n
        return None
    
    while(True):
        current = find_body(current)
        if current == None:
            return ".".join(scope)

class Codeql_parser:    
    def collect(self, report_dir, mapping_file):
        file = open(mapping_file, 'w')
        nameset = set()
        
        if not os.path.exists(report_dir):
            print("Not completely tested yet!")
            return            
        
        for report in os.listdir(report_dir):
            data = pd.read_csv(report_dir + report, names = ['1', '2', '3', '4', '5', '6', '7', '8', '9'])
            for i in range(len(data.axes[0])):
                #print(data.iloc[i, 0])
                nameset.add(data.iloc[i, 0])
            
        for i in nameset:
            file.write(i + '\n')
        
        file.close()
    
    # ground_truth: {case_name: {cwe, location}}
    def evaluate(self, report_dir, ground_truth, cwe_mapping, DatasetRoot):
        
        TP = []
        TN = []
        FP = []
        FN = []
        
        for report in os.listdir(report_dir):
            
            report_path = report_dir + "/" + report
            
            full_name = report.split(".")[0]
            case_name = full_name[:-4]
            case_cwe = full_name[:full_name.find("_")]
            expectation = True if full_name[-3:] == "vul" else False
            
            answer = ground_truth[case_name]
            result = pd.read_csv(report_path, names = ['1', '2', '3', '4', '5', '6', '7', '8', '9'])
            
            result_is_right = False
            # Verify the result
            for index, row in result.iterrows():
                
                des = row['1']
                
                cwe = ""
                try:
                    cwe = cwe_mapping[des] # map description to cwe
                except:
                    print("This description not mapped: ", end="")
                    print(des)
                    return
                
                # First, check cwe
                right_cwe = False
                for i in cwe:
                    if i == answer['cwe']:
                        # cwe is right
                        right_cwe = True
                        break
                if right_cwe == False:
                    #log.write("\n")
                    continue
                
                # Then, check location
                file = row['5'][1:]
                line_num = row['6']
                
                # parse the source file with ast library
                abs_file = DatasetRoot + "/" + case_cwe + "/" + file
                func_name = getFunc(abs_file, line_num)
                    
                if func_name == answer['location']:
                    result_is_right = True
                    break
            
            if result_is_right == True:
                if expectation == True:
                    TP.append(full_name)
                else:
                    FP.append(full_name)
            else:
                if expectation == True:
                    FN.append(full_name)
                else:
                    TN.append(full_name)
                    
        print("TP: ", end="") 
        print(TP)
        print("TN: ", end="") 
        print(TN)
        print("FP: ", end="") 
        print(FP)
        print("FN: ", end="") 
        print(FN)
        
        num_TP = len(TP)
        num_TN = len(TN)
        num_FP = len(FP)
        num_FN = len(FN)
        
        Precision = num_TP / (num_TP + num_FP) if (num_TP + num_FP) > 0 else 0
        Recall = num_TP / (num_TP + num_FN) if (num_TP + num_FN) > 0 else 0
        F1 = 2 * Precision * Recall / (Precision + Recall) if (Precision + Recall) > 0 else 0
        print("Precision:   %s"% Precision)
        print("Recall:      %s"% Recall)
        print("F1:          %s"% F1)


class Pysa_parser:
    def collect(self, report_dir, mapping_file):
        file = open(mapping_file, 'w')
        nameset = set()
        
        if not os.path.exists(report_dir):
            print("Not completely tested yet!")
            return            
        
        for case in os.listdir(report_dir):
            report_path = report_dir + "/" + case + "/errors.json"
            if not os.path.exists(report_path):
                # no error
                continue
            
            report = open(report_path)
            errors = json.load(report)
            for error in errors:
                nameset.add(error['name'])
            report.close()
            
        for i in nameset:
            file.write(i + '\n')
        
        file.close()
    
    # ground_truth: {case_name: {cwe, location}}
    def evaluate(self, report_dir, ground_truth, cwe_mapping, DatasetRoot):
        
        TP = []
        TN = []
        FP = []
        FN = []
        
        Failed = []
        
        for report in os.listdir(report_dir):
            
            report_path = report_dir + "/" + report
            
            case_name = report[:-4]
            case_cwe = report[:report.find("_")]
            expectation = True if report[-3:] == "vul" else False
            
            answer = ground_truth[case_name]
            
            result_path = report_path + "/result.sarif"
            error_path = report_path + "/errors.json"
            if not os.path.exists(error_path):
                # no error
                Failed.append(report)
                continue
            
            f = open(error_path)
            errors = json.load(f)
            f.close()
            
            if len(errors) == 0:
                if expectation == True:
                    FN.append(report)
                else:
                    TN.append(report)
                continue
            
            f = open(result_path)
            results = json.load(f)
            results = results['runs'][0]['results']
            f.close()
            
            
            
            result_is_right = False
            # Verify the result
            for result in errors:
                
                des = result['name']
                
                cwe = ""
                try:
                    cwe = cwe_mapping[des] # map description to cwe
                except:
                    print("This description not mapped: ", end="")
                    print(des)
                    return
                
                # First, check cwe
                right_cwe = False
                for i in cwe:
                    if i == answer['cwe']:
                        # cwe is right
                        right_cwe = True
                        break
                if right_cwe == False:
                    #log.write("\n")
                    continue
                
                # Then, check location
                file = result['path']
                line_num = result['line']
                if file == '*':  # maybe sink lies in library
                    continue
                
                abs_file = ""
                line = 0
                for result in results:
                    if result['locations'][0]['physicalLocation']['artifactLocation']['uri'] == file and \
                       result['locations'][0]['physicalLocation']['region']['startLine'] == line_num:
                        trace = result['codeFlows'][0]['threadFlows'][0]['locations']
                        for node in reversed(trace):
                            if node['location']['physicalLocation']['artifactLocation']['uri'] == None:
                                continue
                            uri = node['location']['physicalLocation']['artifactLocation']['uri']
                            abs_file = DatasetRoot + "/" + case_cwe + "/" + uri
                            line = node['location']['physicalLocation']['region']['startLine']
                            break
                        break
                        
                func_name = getFunc(abs_file, line)
                    
                if func_name == answer['location']:
                    result_is_right = True
                    break
            
            if result_is_right == True:
                if expectation == True:
                    TP.append(report)
                else:
                    FP.append(report)
            else:
                if expectation == True:
                    FN.append(report)
                else:
                    TN.append(report)
                    
        print("TP: ", end="") 
        print(TP)
        print("TN: ", end="") 
        print(TN)
        print("FP: ", end="") 
        print(FP)
        print("FN: ", end="") 
        print(FN)
        
        num_TP = len(TP)
        num_TN = len(TN)
        num_FP = len(FP)
        num_FN = len(FN)
        
        Precision = num_TP / (num_TP + num_FP) if (num_TP + num_FP) > 0 else 0
        Recall = num_TP / (num_TP + num_FN) if (num_TP + num_FN) > 0 else 0
        F1 = 2 * Precision * Recall / (Precision + Recall) if (Precision + Recall) > 0 else 0
        print("Precision:   %s"% Precision)
        print("Recall:      %s"% Recall)
        print("F1:          %s"% F1)


class Semgrep_parser:
    def collect(self, report_dir, mapping_file):
        file = open(mapping_file, 'w')
        nameset = set()
        
        if not os.path.exists(report_dir):
            print("Not completely tested yet!")
            return            
        
        for report in os.listdir(report_dir):
            report_path = report_dir + "/" + report
            
            report_f = open(report_path)
            report_content = json.load(report_f)
            
            results = report_content['results']
            
            for result in results:
                
                if result['extra']['metadata']['category'] != 'security':
                    continue
                
                des = result['check_id'].split('.')[-2:]
                des = ".".join(des)
                
                nameset.add(des)

            report.close()
            
        for i in nameset:
            file.write(i + '\n')
        
        file.close()

    # ground_truth: {case_name: {cwe, location}}
    def evaluate(self, report_dir, ground_truth, cwe_mapping, DatasetRoot):
        
        TP = []
        TN = []
        FP = []
        FN = []
        
        for report in os.listdir(report_dir):
            
            report_path = report_dir + "/" + report
            
            full_name = report.split(".")[0]
            case_name = full_name[:-4]
            case_cwe = full_name[:full_name.find("_")]
            expectation = True if full_name[-3:] == "vul" else False
            
            answer = ground_truth[case_name]

            report_f = open(report_path)
            results = json.load(report_f)
            results = results['results']
            report_f.close()
            
            result_is_right = False
            # Verify the result
            for result in results:
                
                if result['extra']['metadata']['category'] != 'security':
                    continue
                
                des = result['check_id'].split('.')[-2:]
                des = ".".join(des)
                
                try:
                    cwe = cwe_mapping[des] # map description to cwe
                except:
                    print("This description not mapped: ", end="")
                    print(des)
                    return
                
                # First, check cwe
                #log.write("True CWE: " + ",".join(answer['cwe']) + "    " + "Rep CWE: " + ",".join(cwe) + "    ")
                right_cwe = False
                for i in cwe:
                    if i == answer['cwe']:
                        # cwe is right
                        right_cwe = True
                        break
                if right_cwe == False:
                    #log.write("\n")
                    continue
                
                # Then, check location
                file:str = result['path']
                file = file[file.find("/target/") + len('/target/'):]
                abs_file = DatasetRoot + "/" + case_cwe + "/" + file
                line_num = result['start']['line']
                
                # parse the source file with ast library
                func_name = getFunc(abs_file, line_num)
                    
                if func_name == answer['location']:
                    result_is_right = True
                    break
            
            if result_is_right == True:
                if expectation == True:
                    TP.append(full_name)
                else:
                    FP.append(full_name)
            else:
                if expectation == True:
                    FN.append(full_name)
                else:
                    TN.append(full_name)
                    
        print("TP: ", end="") 
        print(TP)
        print("TN: ", end="") 
        print(TN)
        print("FP: ", end="") 
        print(FP)
        print("FN: ", end="") 
        print(FN)
        
        num_TP = len(TP)
        num_TN = len(TN)
        num_FP = len(FP)
        num_FN = len(FN)
        
        Precision = num_TP / (num_TP + num_FP) if (num_TP + num_FP) > 0 else 0
        Recall = num_TP / (num_TP + num_FN) if (num_TP + num_FN) > 0 else 0
        F1 = 2 * Precision * Recall / (Precision + Recall) if (Precision + Recall) > 0 else 0
        print("Precision:   %s"% Precision)
        print("Recall:      %s"% Recall)
        print("F1:          %s"% F1)
    

class Snyk_parser:
    def collect(self, report_dir, mapping_file):
        file = open(mapping_file, 'w')
        nameset = set()
        
        if not os.path.exists(report_dir):
            print("Not completely tested yet!")
            return            
        
        for report in os.listdir(report_dir):
            report_path = report_dir + "/" + report
            
            report_f = open(report_path)
            report_content = json.load(report_f)
            report_f.close()
            
            results = report_content['runs'][0]['results']
            
            for result in results:
                
                if 'python' not in result['ruleId']:
                    continue
                
                message = result['message']['markdown']
                
                nameset.add(message)
                    
        for i in nameset:
            file.write(i + '\n')
        
        file.close()

    # ground_truth: {case_name: {cwe, location}}
    def evaluate(self, report_dir, ground_truth, cwe_mapping, DatasetRoot):
        
        TP = []
        TN = []
        FP = []
        FN = []
        
        for report in os.listdir(report_dir):
            
            report_path = report_dir + "/" + report
            
            full_name = report.split(".")[0]
            case_name = full_name[:-4]
            case_cwe = full_name[:full_name.find("_")]
            expectation = True if full_name[-3:] == "vul" else False
            
            answer = ground_truth[case_name]

            report_f = open(report_path)
            results = json.load(report_f)
            results = results['runs'][0]['results']
            report_f.close()
            
            result_is_right = False
            # Verify the result
            for result in results:
                
                if 'python' not in result['ruleId']:
                    continue
                
                des = result['message']['markdown']
                
                try:
                    cwe = cwe_mapping[des] # map description to cwe
                except:
                    print("This description not mapped: ", end="")
                    print(des)
                    return
                
                # First, check cwe
                #log.write("True CWE: " + ",".join(answer['cwe']) + "    " + "Rep CWE: " + ",".join(cwe) + "    ")
                right_cwe = False
                for i in cwe:
                    if i == answer['cwe']:
                        # cwe is right
                        right_cwe = True
                        break
                if right_cwe == False:
                    #log.write("\n")
                    continue
                
                # Then, check location
                files = result['locations']
                file = ''
                line_num = 0
                if isinstance(files, list):
                    if len(files) > 1:
                        print("Not only one location!")
                        print(report)
                        print(result)
                        return
                    file = files[0]['physicalLocation']['artifactLocation']['uri']
                    line_num = files[0]['physicalLocation']['region']['startLine']
                else:
                    print("Not list!")
                    print(report)
                    print(result)
                    return
                
                abs_file = DatasetRoot + "/" + case_cwe + "/" + file
                
                # parse the source file with ast library
                func_name = getFunc(abs_file, line_num)
                    
                if func_name == answer['location']:
                    result_is_right = True
                    break
            
            if result_is_right == True:
                if expectation == True:
                    TP.append(full_name)
                else:
                    FP.append(full_name)
            else:
                if expectation == True:
                    FN.append(full_name)
                else:
                    TN.append(full_name)
                    
        print("TP: ", end="") 
        print(TP)
        print("TN: ", end="") 
        print(TN)
        print("FP: ", end="") 
        print(FP)
        print("FN: ", end="") 
        print(FN)
        
        num_TP = len(TP)
        num_TN = len(TN)
        num_FP = len(FP)
        num_FN = len(FN)
        
        Precision = num_TP / (num_TP + num_FP) if (num_TP + num_FP) > 0 else 0
        Recall = num_TP / (num_TP + num_FN) if (num_TP + num_FN) > 0 else 0
        F1 = 2 * Precision * Recall / (Precision + Recall) if (Precision + Recall) > 0 else 0
        print("Precision:   %s"% Precision)
        print("Recall:      %s"% Recall)
        print("F1:          %s"% F1)


class Bandit_parser:
    def collect(self, report_dir, mapping_file):
        file = open(mapping_file, 'w')
        nameset = set()
        
        if not os.path.exists(report_dir):
            print("Not completely tested yet!")
            return            
        
        for report in os.listdir(report_dir):
            report_path = report_dir + "/" + report
            
            report_f = open(report_path)
            report_content = json.load(report_f)
            report_f.close()
            
            results = report_content['results']
            
            for result in results:
                
                try:
                    cwe = result['issue_cwe']
                except:
                    print("no cwe!")
                
                message = result['test_name']
                nameset.add(message)
                    
        for i in nameset:
            file.write(i + '\n')
        
        file.close()
        
    # ground_truth: {case_name: {cwe, location}}
    def evaluate(self, report_dir, ground_truth, cwe_mapping, DatasetRoot):
        
        TP = []
        TN = []
        FP = []
        FN = []
        
        for report in os.listdir(report_dir):
            
            report_path = report_dir + "/" + report
            
            full_name = report.split(".")[0]
            case_name = full_name[:-4]
            case_cwe = full_name[:full_name.find("_")]
            expectation = True if full_name[-3:] == "vul" else False
            
            answer = ground_truth[case_name]

            report_f = open(report_path)
            results = json.load(report_f)
            results = results['results']
            report_f.close()
            
            result_is_right = False
            # Verify the result
            for result in results:
                
                if 'issue_cwe' not in result.keys():
                    print("There's no cwe")
                    print(result)
                
                des = result['test_name']
                
                try:
                    cwe = cwe_mapping[des] # map description to cwe
                except:
                    print("This description not mapped: ", end="")
                    print(des)
                    return
                
                # First, check cwe
                #log.write("True CWE: " + ",".join(answer['cwe']) + "    " + "Rep CWE: " + ",".join(cwe) + "    ")
                right_cwe = False
                for i in cwe:
                    if i == answer['cwe']:
                        # cwe is right
                        right_cwe = True
                        break
                if right_cwe == False:
                    #log.write("\n")
                    continue
                
                # Then, check location
                file = result['filename']
                file = file[file.find("/target/") + len('/target/'):]
                line_num = result["line_number"]
                
                abs_file = DatasetRoot + "/" + case_cwe + "/" + file
                
                # parse the source file with ast library
                func_name = getFunc(abs_file, line_num)
                    
                if func_name == answer['location']:
                    result_is_right = True
                    break
            
            if result_is_right == True:
                if expectation == True:
                    TP.append(full_name)
                else:
                    FP.append(full_name)
            else:
                if expectation == True:
                    FN.append(full_name)
                else:
                    TN.append(full_name)
                    
        print("TP: ", end="") 
        print(TP)
        print("TN: ", end="") 
        print(TN)
        print("FP: ", end="") 
        print(FP)
        print("FN: ", end="") 
        print(FN)
        
        num_TP = len(TP)
        num_TN = len(TN)
        num_FP = len(FP)
        num_FN = len(FN)
        
        Precision = num_TP / (num_TP + num_FP) if (num_TP + num_FP) > 0 else 0
        Recall = num_TP / (num_TP + num_FN) if (num_TP + num_FN) > 0 else 0
        F1 = 2 * Precision * Recall / (Precision + Recall) if (Precision + Recall) > 0 else 0
        print("Precision:   %s"% Precision)
        print("Recall:      %s"% Recall)
        print("F1:          %s"% F1)
    
    
class DevSkim_parser:
    def collect(self, report_dir, mapping_file):
        file = open(mapping_file, 'w')
        nameset = set()
        
        if not os.path.exists(report_dir):
            print("Not completely tested yet!")
            return            
        
        for report in os.listdir(report_dir):
            report_path = report_dir + "/" + report
            
            report_f = open(report_path)
            report_content = json.load(report_f)
            report_f.close()
            
            results = report_content['runs'][0]['results']
            
            for result in results:
                
                if result["locations"][0]["physicalLocation"]["region"]["sourceLanguage"] != "python":
                    continue
                
                message = result['message']['text']
                
                nameset.add(message)
                    
        for i in nameset:
            file.write(i + '\n')
        
        file.close()

    # ground_truth: {case_name: {cwe, location}}
    def evaluate(self, report_dir, ground_truth, cwe_mapping, DatasetRoot):
        
        TP = []
        TN = []
        FP = []
        FN = []
        
        for report in os.listdir(report_dir):
            
            report_path = report_dir + "/" + report
            
            full_name = report.split(".")[0]
            case_name = full_name[:-4]
            case_cwe = full_name[:full_name.find("_")]
            expectation = True if full_name[-3:] == "vul" else False
            
            answer = ground_truth[case_name]

            report_f = open(report_path)
            results = json.load(report_f)
            results = results['runs'][0]['results']
            report_f.close()
            
            result_is_right = False
            # Verify the result
            for result in results:
                
                if result["locations"][0]["physicalLocation"]["region"]["sourceLanguage"] != "python":
                    continue
                
                des = result['message']['text']
                
                try:
                    cwe = cwe_mapping[des] # map description to cwe
                except:
                    print("This description not mapped: ", end="")
                    print(des)
                    return
                
                # First, check cwe
                #log.write("True CWE: " + ",".join(answer['cwe']) + "    " + "Rep CWE: " + ",".join(cwe) + "    ")
                right_cwe = False
                for i in cwe:
                    if i == answer['cwe']:
                        # cwe is right
                        right_cwe = True
                        break
                if right_cwe == False:
                    #log.write("\n")
                    continue
                
                # Then, check location
                files = result['locations']
                file = ''
                line_num = 0
                if isinstance(files, list):
                    if len(files) > 1:
                        print("Not only one location!")
                        print(report)
                        print(result)
                        return
                    file = files[0]['physicalLocation']['artifactLocation']['uri']
                    line_num = files[0]['physicalLocation']['region']['startLine']
                else:
                    print("Not list!")
                    print(report)
                    print(result)
                    return
                
                abs_file = DatasetRoot + "/" + case_cwe + "/" + file
                
                # parse the source file with ast library
                func_name = getFunc(abs_file, line_num)
                    
                if func_name == answer['location']:
                    result_is_right = True
                    break
            
            if result_is_right == True:
                if expectation == True:
                    TP.append(full_name)
                else:
                    FP.append(full_name)
            else:
                if expectation == True:
                    FN.append(full_name)
                else:
                    TN.append(full_name)
                    
        print("TP: ", end="") 
        print(TP)
        print("TN: ", end="") 
        print(TN)
        print("FP: ", end="") 
        print(FP)
        print("FN: ", end="") 
        print(FN)
        
        num_TP = len(TP)
        num_TN = len(TN)
        num_FP = len(FP)
        num_FN = len(FN)
        
        Precision = num_TP / (num_TP + num_FP) if (num_TP + num_FP) > 0 else 0
        Recall = num_TP / (num_TP + num_FN) if (num_TP + num_FN) > 0 else 0
        F1 = 2 * Precision * Recall / (Precision + Recall) if (Precision + Recall) > 0 else 0
        print("Precision:   %s"% Precision)
        print("Recall:      %s"% Recall)
        print("F1:          %s"% F1)


class Bearer_parser:
    def collect(self, report_dir, mapping_file):
        file = open(mapping_file, 'w')
        nameset = set()
        
        if not os.path.exists(report_dir):
            print("Not completely tested yet!")
            return            
        
        for report in os.listdir(report_dir):
            report_path = report_dir + "/" + report
            
            report_f = open(report_path)
            report_content = json.load(report_f)
            report_f.close()
            
            for level in report_content.keys():
                results = report_content[level]
            
                for result in results:
                    
                    message = result['id']
                    
                    nameset.add(message)
                        
        for i in nameset:
            file.write(i + '\n')
        
        file.close()

    # ground_truth: {case_name: {cwe, location}}
    def evaluate(self, report_dir, ground_truth, cwe_mapping, DatasetRoot):
        
        TP = []
        TN = []
        FP = []
        FN = []
        
        for report in os.listdir(report_dir):
            
            report_path = report_dir + "/" + report
            
            full_name = report.split(".")[0]
            case_name = full_name[:-4]
            case_cwe = full_name[:full_name.find("_")]
            expectation = True if full_name[-3:] == "vul" else False
            
            answer = ground_truth[case_name]

            report_f = open(report_path)
            report_content = json.load(report_f)
            report_f.close()
            
            result_is_right = False
            for level in report_content.keys():
                results = report_content[level]
            
                # Verify the result
                for result in results:
                    
                    des = result['id']
                    
                    try:
                        cwe = cwe_mapping[des] # map description to cwe
                    except:
                        print("This description not mapped: ", end="")
                        print(des)
                        return
                    
                    # First, check cwe
                    #log.write("True CWE: " + ",".join(answer['cwe']) + "    " + "Rep CWE: " + ",".join(cwe) + "    ")
                    right_cwe = False
                    for i in cwe:
                        if i == answer['cwe']:
                            # cwe is right
                            right_cwe = True
                            break
                    if right_cwe == False:
                        #log.write("\n")
                        continue
                    
                    # Then, check location
                    file = result['full_filename']
                    file = file[file.find("/target/") + len('/target/'):]
                    line_num = result['line_number']
                    
                    abs_file = DatasetRoot + "/" + case_cwe + "/" + file
                    
                    # parse the source file with ast library
                    func_name = getFunc(abs_file, line_num)
                        
                    if func_name == answer['location']:
                        result_is_right = True
                        break
                
            if result_is_right == True:
                if expectation == True:
                    TP.append(full_name)
                else:
                    FP.append(full_name)
            else:
                if expectation == True:
                    FN.append(full_name)
                else:
                    TN.append(full_name)
                    
        print("TP: ", end="") 
        print(TP)
        print("TN: ", end="") 
        print(TN)
        print("FP: ", end="") 
        print(FP)
        print("FN: ", end="") 
        print(FN)
        
        num_TP = len(TP)
        num_TN = len(TN)
        num_FP = len(FP)
        num_FN = len(FN)
        
        Precision = num_TP / (num_TP + num_FP) if (num_TP + num_FP) > 0 else 0
        Recall = num_TP / (num_TP + num_FN) if (num_TP + num_FN) > 0 else 0
        F1 = 2 * Precision * Recall / (Precision + Recall) if (Precision + Recall) > 0 else 0
        print("Precision:   %s"% Precision)
        print("Recall:      %s"% Recall)
        print("F1:          %s"% F1)


class Dlint_parser:
    def collect(self, report_dir, mapping_file):
        file = open(mapping_file, 'w')
        nameset = set()
        
        if not os.path.exists(report_dir):
            print("Not completely tested yet!")
            return            
        
        for report in os.listdir(report_dir):
            report_path = report_dir + "/" + report
            
            report_f = open(report_path)
            report_content = report_f.readlines()
            report_f.close()
            
            for line in report_content:
                
                message = line.split(": ")[1].strip()
                
                nameset.add(message)
                    
        for i in nameset:
            file.write(i + '\n')
        
        file.close()

    # ground_truth: {case_name: {cwe, location}}
    def evaluate(self, report_dir, ground_truth, cwe_mapping, DatasetRoot):
        
        TP = []
        TN = []
        FP = []
        FN = []
        
        for report in os.listdir(report_dir):
            
            report_path = report_dir + "/" + report
            
            full_name = report.split(".")[0]
            case_name = full_name[:-4]
            case_cwe = full_name[:full_name.find("_")]
            expectation = True if full_name[-3:] == "vul" else False
            
            answer = ground_truth[case_name]

            report_f = open(report_path)
            report_content = report_f.readlines()
            report_f.close()
            
            result_is_right = False
            
                # Verify the result
            for line in report_content:
                
                des = line.split(": ")[1].strip()
                
                try:
                    cwe = cwe_mapping[des] # map description to cwe
                except:
                    print("This description not mapped: ", end="")
                    print(des)
                    return
                
                # First, check cwe
                #log.write("True CWE: " + ",".join(answer['cwe']) + "    " + "Rep CWE: " + ",".join(cwe) + "    ")
                right_cwe = False
                for i in cwe:
                    if i == answer['cwe']:
                        # cwe is right
                        right_cwe = True
                        break
                if right_cwe == False:
                    #log.write("\n")
                    continue
                
                # Then, check location
                full_location = line.split(": ")[0]
                file = full_location.split(":")[0]
                file = file[file.find("/target/") + len('/target/'):]
                line_num = int(full_location.split(":")[1])
                
                abs_file = DatasetRoot + "/" + case_cwe + "/" + file
                
                # parse the source file with ast library
                func_name = getFunc(abs_file, line_num)
                    
                if func_name == answer['location']:
                    result_is_right = True
                    break
            
            if result_is_right == True:
                if expectation == True:
                    TP.append(full_name)
                else:
                    FP.append(full_name)
            else:
                if expectation == True:
                    FN.append(full_name)
                else:
                    TN.append(full_name)
                    
        print("TP: ", end="") 
        print(TP)
        print("TN: ", end="") 
        print(TN)
        print("FP: ", end="") 
        print(FP)
        print("FN: ", end="") 
        print(FN)
        
        num_TP = len(TP)
        num_TN = len(TN)
        num_FP = len(FP)
        num_FN = len(FN)
        
        Precision = num_TP / (num_TP + num_FP) if (num_TP + num_FP) > 0 else 0
        Recall = num_TP / (num_TP + num_FN) if (num_TP + num_FN) > 0 else 0
        F1 = 2 * Precision * Recall / (Precision + Recall) if (Precision + Recall) > 0 else 0
        print("Precision:   %s"% Precision)
        print("Recall:      %s"% Recall)
        print("F1:          %s"% F1)
