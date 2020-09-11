# iq-license-bom
Output the license BOM for applications in IQ

A common request is to create a bill of materials for application license data.  This sample script will output a report of the licenses and their threat groups for a giving component.  You can pass in a publicId to focus on one application or leave it blank to get all applications and stages

command
python iq_license_bom.py -a 'admin:admin123' -u 'http://localhost:8070' -i 'sandbox-application'

Additional fields can be added to the getReportData() function via the 'headers' field and adding objects to the 'components' container.
