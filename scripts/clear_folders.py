import os
import shutil

#"\\?\"to overcome MAX_PATH(260) limit
#root = u"\\\\?\\" + u"D:\\Research\\Project\\SASTcomparison\\CVECollection"

root = "/home/nkamg/SASTcomparison/CVECollection/"

#print(os.listdir(root))
for cve in os.listdir(root):
    cve = os.path.join(root, cve)
    for file in os.listdir(cve):
        if ".zip" not in file:
            file = os.path.join(cve, file)
            print(os.path.abspath(file))
            shutil.rmtree(file)