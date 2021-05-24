import flask
from flask import request, jsonify
import urllib.request
from urllib.request import urlopen
import urllib

app = flask.Flask(__name__)
app.config["DEBUG"] = True

# known bad user agents to block
#suspect_vendor = ["cisco", "friendly-scanner", "sipcli", "sipvicious", "sip-scan", "sipsak", "sundayddr", "iWar", "CSipSimple", "SIVuS", "Gulp", "sipv",  "smap", "friendly-request", "VaxIPUserAgent", "VaxSIPUserAgent", "siparmyknife", "Test Agent", "PortSIP VoIP SDK 11.2", "ABTO Video SIP SDK", "Asterisk PBX", "PortSIP VoIP SDK", "eyeBeam release 3015c stamp 27107"]

ua_file_url = "https://aledpolicyserverpub1.blob.core.windows.net/public-bad-useragent-list/bad_ua_list.txt"

suspect_vendor =[]

content=urllib.request.urlopen(ua_file_url)  
    
for line in content:
    decoded = line.decode('utf-8').strip()
    suspect_vendor.append(decoded)

print(suspect_vendor)


@app.route('/policy/v1/service/configuration', methods=['GET'])
def api_id():

    call_direction = request.args['call_direction']
    user_agent = request.args['vendor']

    if call_direction == 'dial_in':
        if user_agent in suspect_vendor:
            # reject the call
            
            policy_response =                 {
                    "status" : "success",
                    "action" : "reject",
                    "reason" : "Known bad user agent, Bang Bang!"
                }
                
                

        else:
            # permit the call
            policy_response =                 {
                    "status" : "success",
                    "action" : "continue"
                }
                

    else:
        # permit the call
        policy_response =                 {
                    "status" : "success",
                    "action" : "continue"
                }
                

    # return the api response
    return jsonify(policy_response)


app.run()