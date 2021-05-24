

def spam_policy(request):
    """ 
    External Policy script to block spam calls based on known bad user agent strings
    Written for Google Cloud Functions.

    Only allows GET requests, will error if any toher methog is used.

    Pexip Policy documentation: https://docs.pexip.com/admin/integrate_policy.htm

    """
    from flask import abort, jsonify

    suspect_vendor = ["cisco", "friendly-scanner", "sipcli", "sipvicious", "sip-scan", "sipsak", "sundayddr", "iWar", "CSipSimple", "SIVuS", "Gulp", "sipv",  "smap", "friendly-request", "VaxIPUserAgent", "VaxSIPUserAgent", "siparmyknife", "Test Agent", "PortSIP VoIP SDK 11.2", "ABTO Video SIP SDK", "Asterisk PBX", "PortSIP VoIP SDK", "eyeBeam release 3015c stamp 27107", "ciscovoipswichpbx"]

    if request.method == 'GET':
        
        # grab values to check
        call_direction = request.args['call_direction']
        user_agent = request.args['vendor']

        if call_direction == 'dial_in':
            if user_agent in suspect_vendor:
                # reject the call - UA known to be bad            
                policy_response =                 {
                        "status" : "success",
                        "action" : "reject",
                        "reason" : "Known bad user agent, " + user_agent + ", Bang Bang!"
                    }           
                
            else:
                # permit the call - not a known bad UA
                policy_response =                 {
                        "status" : "success",
                        "action" : "continue"
                    }
                
        else:
            # permit the call - call is not inbound
            policy_response =                 {
                        "status" : "success",
                        "action" : "continue"
                    }
        
        # return the api response
        return jsonify(policy_response)
        
    elif request.method == 'PUT':
        return abort(403)
    else:
        return abort(405)