

def spam_policy(request):
    """ 
    External Policy script to block spam calls based on known bad user agent strings
    Written for Google Cloud Functions.

    Only allows GET requests, will error if any other methog is used.

    Pexip Policy documentation: https://docs.pexip.com/admin/integrate_policy.htm

    """
    from flask import abort, jsonify

    # grab values from the request to check
    call_direction = request.args['call_direction']
    user_agent = request.args['vendor']
    ua_lower = user_agent.lower()
    
    # policy responses
    success_continue =  {
                            "status" : "success",
                            "action" : "continue"
                        }

    fail_reject =   {
                        "status" : "success",
                        "action" : "reject",
                        "reason" : "Known bad user agent, " + user_agent + ", Bang Bang!"
                    }

    # the list of known bad user agents
    suspect_vendor = ["cisco", "Cisco", "friendly-scanner", "sipcli", "sipvicious", "sip-scan", "sipsak", "sundayddr", "iWar", "CSipSimple", "SIVuS", "Gulp", "sipv",  "smap", "friendly-request", "VaxIPUserAgent", "VaxSIPUserAgent", "siparmyknife", "Test Agent", "PortSIP VoIP SDK 11.2", "ABTO Video SIP SDK", "Asterisk PBX", "PortSIP VoIP SDK", "eyeBeam release 3015c stamp 27107", "ciscovoipswichpbx", "ciscovoipswichpbx123", "SIPADMINPBXCISCOOO123", "SIPFPBXciscooo" ]
    
    # prefix of the the most popular known bad user agents
    most_wanted = [ "portsip", "eyebeam", "ciscovoip", "sipadmin", "sipfpbx" ]
    
    if request.method == 'GET':
        
        match = False

        if call_direction == 'dial_in':
            
            for ua in most_wanted:
            
                if ua_lower.startswith(ua) == True:
                    # reject the call - UA known to be bad 
                    policy_response = fail_reject
                    #log the rejection
                    print("Blocked User Agent: " + user_agent)
                    match=True

            if match==False:
                if user_agent in suspect_vendor:
                    # reject the call - UA known to be bad            
                    policy_response = fail_reject
                    #log the rejection
                    print("Blocked User Agent: " + user_agent)    
                
                else:
                    # permit the call - not a known bad UA
                    policy_response = success_continue
                
        else:
            # permit the call - call is not inbound
            policy_response = success_continue
        
        # return the api response
        return jsonify(policy_response)
        
    elif request.method == 'PUT':
        return abort(403)
    else:
        return abort(405)
