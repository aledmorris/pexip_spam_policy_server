Goal of the repo is to demonstrate how to make use of the public cloud to host a simple external policy server, for the purpose of mitigating spam calls.

The cloud based function receives a policy request from Pexip Infinity and check if the user agent for the call matches any know bad user agent strings.

Pexip Infinity External Policy reference documentation can be found here: https://docs.pexip.com/admin/external_policy_requests.htm


- **app.py** = Flask app to demonstrate the concept in a general sense.

- **cloud_func.py** = example script to be used with Google Cloud Functions.

- **lambda_func.py** = example script for use with AWS Lambda


