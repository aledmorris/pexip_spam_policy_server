import json, logging

# Setup logging
logz = logging.getLogger(__name__)
logz.setLevel(logging.INFO)


def lambda_handler(event, context):
    
    # the list of known bad user agents
    suspect_vendor = ["cisco", "Cisco", "friendly-scanner", "sipcli", "sipvicious", "sip-scan", "sipsak", "sundayddr", "iWar", "CSipSimple", "SIVuS", "Gulp", "sipv",  "smap", "friendly-request", "VaxIPUserAgent", "VaxSIPUserAgent", "siparmyknife", "Test Agent", "PortSIP VoIP SDK 11.2", "ABTO Video SIP SDK", "Asterisk PBX", "PortSIP VoIP SDK", "eyeBeam release 3015c stamp 27107", "ciscovoipswichpbx", "ciscovoipswichpbx123", "SIPADMINPBXCISCOOO123", "SIPFPBXciscooo", "FRITZ", "dynalink", "ARRIS", "Yealink" ]
    
    # prefix of the the most popular known bad user agents
    most_wanted = [ "portsip", "eyebeam", "ciscovoip", "sipadmin", "sipfpbx", "fpbx", "voippbx", "pbxcisco", "ciscopbx", "sipvoip" ]

    # grab the parameters
    call_direction = event["queryStringParameters"]["call_direction"]
    user_agent = event["queryStringParameters"]["vendor"]
    

    # policy responses
    success_continue = {
                        "status" : "success",
                        "action" : "continue"
                        }

    fail_error = {
                    "status" : "success",
                    "action" : "reject",
                    "reason" : "Bad request"
                    }

    match = False
    
    
    # check if variables are present
    if not call_direction:

        #log the error
        print("Error Bad Request")
        logz.warning('Bad request - call_direction field missing.')

        # send 400
        return {
            'statusCode': 400,
            'body': json.dumps(fail_error)
        }

    elif not user_agent:
        
        #log the error
        print("Error Bad Request")
        logz.warning('Bad request - user_agent field missing.')

        # send 400
        return {
            'statusCode': 400,
            'body': json.dumps(fail_error)
        }

    elif call_direction == 'dial_in':

        ua_lower = user_agent.lower()

        for ua in most_wanted:
            
            if ua_lower.startswith(ua) == True:
                
                # reject the call - UA known to be bad 
                policy_response = {
                                    "status" : "success",
                                    "action" : "reject",
                                    "reason" : "Known bad user agent, " + user_agent + ", Bang Bang!"
                                }
                
                #log the rejection
                print("Blocked User Agent: " + user_agent)
                logz.info('Blocked user agent: ' + user_agent)

                match=True

        if match==False:
            if user_agent in suspect_vendor:
                # reject the call - UA known to be bad 
                policy_response = {
                                    "status" : "success",
                                    "action" : "reject",
                                    "reason" : "Known bad user agent, " + user_agent + ", Bang Bang!"
                                }

                #log the rejection
                print("Blocked User Agent: " + user_agent)
                logz.info('Blocked user agent: ' + user_agent)  
                
            else:
                # permit the call - not a known bad UA
                policy_response = success_continue
                
    else:
        # permit the call - call is not inbound
        policy_response = success_continue

    
    return {
        'statusCode': 200,
        'body': json.dumps(policy_response)
    }
