#!/usr/bin/python3
import sys
import json
import argparse
import requests
 
iq_url, creds, iq_session = "", "", requests.Session()
 
def getArguments():
    global iq_url, iq_session, creds
    parser = argparse.ArgumentParser(description='Output License Report')
    parser.add_argument('-u','--url', help='', default="http://localhost:8070", required=False)
    parser.add_argument('-a','--auth', help='', default="admin:admin123", required=False)
    parser.add_argument('-g','--stage', help='', default="build", required=False)
    parser.add_argument('-i','--publicId', help='', required=False)
    args = vars(parser.parse_args())
    iq_url = args["url"]
    creds = args["auth"].split(":")
    iq_session.auth = requests.auth.HTTPBasicAuth(creds[0], creds[1])
    return args
#-------------------------------
def main():
    args = getArguments()
    publicId = args["publicId"]
    stage = args["stage"]
    filename = "iq_license_bom_report.csv"
 
    #return report for publicId, or all applications/stages.
    if publicId is not None:
        findApplication(publicId, stage, filename)
    else: reportAllApps(filename)
 
#------------------------------------
#   Main report processing
#------------------------------------
def getReportData(app, report):
    url = "{}/{}".format(iq_url, report["reportDataUrl"])
    reportData = iq_session.get(url).json()
    #---------------------------------------
    components, unknown = [],[]
    # set headers to output to csv file.
    headers = ["Application", "Stage", "Component", "License", "ThreatGroup"]
 
    #license and group filters.
    licenseFilter = ["No-Source-License","Not-Supported","No-Sources"]
    threatFilter = ["Sonatype Informational","Sonatype Special Licenses"]
    for c in reportData["components"]:
        if c["packageUrl"] is None: #these are unknowns.
            unknown.append( { c["hash"] : c["pathnames"] } )
        else:
            licenses, groups, data = [], [], c["licenseData"]
            for l in data["declaredLicenses"]:
                if l["licenseId"] not in licenseFilter:
                    licenses.append(l["licenseId"])
            for l in data["observedLicenses"]:
                if l["licenseId"] not in licenseFilter:
                    licenses.append(l["licenseId"])
            for g in data["effectiveLicenseThreats"]:
                if g["licenseThreatGroupName"] not in threatFilter:
                    groups.append( g["licenseThreatGroupName"])
             
            #append row data.
            components.append( [
                app["name"],
                report["stage"],
                cleanPurl(c["packageUrl"]),
                csvList(licenses,":"),
                csvList(groups,":")
            ] )
 
    #Optional, sorting by threat Group [3], then PackageUrl[1]
    components.sort(key = lambda x: (x[3], x[1]))
 
    #return processed report.
    return {"summary": reportData["matchSummary"],
            "application": app,
            "report": report,
            "headers": headers,
            "components":components,
            "unknown":unknown}
 
#------------------------------------
#   Helper Functions
#------------------------------------
def reportAllApps(filename):
    processed, apps = [], getApplications()
    print("Found {} applications.".format(len(apps)))
    for app in apps:
        print("-"*50)
        print("'{}'".format( app["name"] ))
        print("-"*50)
        reports = getReports(app)
        print("- {} reports".format(len(reports)))
        for report in reports:
            print("- processing '{}' report.".format( report["stage"] ))
            data = getReportData(app, report)
            print("=== report contained '{}' components.".format( len(data["components"]) ) )
            processed.append( data )
    print("*** {} reports processed ***".format(len(processed)))
    outputCSV(processed, filename)
 
 
def findApplication(publicId, stage, filename):
    app = getApp(publicId)
    data = getReportStage(app, stage)
    if data is not None:
        outputCSV(data, filename)
 
def getApplications(): #returns array of all applications
    url = '{}/api/v2/applications'.format(iq_url)
    response = iq_session.get(url)
    if response.status_code != requests.codes.ok:
        print("Error trying to find applications");
        print(url); print(response); sys.exit(1)
    apps = response.json()["applications"]
    if len(apps) == 0:
        print("Cannot find applications '{}'".format(publicId)); sys.exit(1)
    return apps
 
def getApp(publicId): # return a single application
    url = '{}/api/v2/applications?publicId={}'.format(iq_url, publicId)
    response = iq_session.get(url)
    if response.status_code != requests.codes.ok:
        print("Error trying to find app '{}'".format(publicId))
        print(url); print(response); sys.exit(1)
    apps = response.json()["applications"]
    if len(apps) == 0: print("Cannot find app '{}'".format(publicId)); sys.exit(1)
    return apps[0]
 
 
def getReportStage(app, stage):
    for report in getReports(app):
        if report["stage"] == stage:
            return [getReportData(app, report)]
    print("Did not find report stage for '{}'".format(app["publicId"]))
 
def getReports(app):
    appId, publicId =  app["id"], app["publicId"]
    url = "{}/api/v2/reports/applications/{}".format(iq_url, appId)
    response = iq_session.get(url)
    if response.status_code != requests.codes.ok:
        print("Error trying to find reports for '{}'".format(publicId))
        print(url); print(response); sys.exit(1)
    results = response.json()
    return results
 
def cleanPurl(purl):
    return str(purl.split("?")[0])
 
def outputCSV(dataArray, filename):
    i=0
    with open(filename,'w') as f:
        for data in dataArray:
            if i==0: f.write(",".join(data['headers'])+"\n")
            i+=1
            for c in data['components']:
                f.write(",".join(c)+"\n")
    print("Saved {} reports to {}".format(i, filename))
 
def csvList(mList,delim=":"): #make values unique, sorted, and aggrigate by delimiter.
    return delim.join( sorted( list( dict.fromkeys( mList ).keys() ) ) )
 
#-----------------------------------------------------------------------------
# run main on launch
#-----------------------------------------------------------------------------
if __name__ == "__main__":
    main()
