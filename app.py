import flask
from flask import request, jsonify

app = flask.Flask(__name__)
app.config["DEBUG"] = True

# known bad user agents to block
suspect_vendor = ["cisco", "friendly-scanner", "sipcli", "sipvicious", "sip-scan", "sipsak", "sundayddr", "iWar", "CSipSimple", "SIVuS", "Gulp", "sipv",  "smap", "friendly-request", "VaxIPUserAgent", "VaxSIPUserAgent", "siparmyknife", "Test Agent", "PortSIP VoIP SDK 11.2", "ABTO Video SIP SDK", "Asterisk PBX", "PortSIP VoIP SDK", "eyeBeam release 3015c stamp 27107"]



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