import requests
import sys
import json
import boto3

dry_run = False
security_group_list = ["sg-kwh6h63v7jh6999", "sg-v2padcege9zbmrg"]
google_endpoint = "https://www.gstatic.com/ipranges/goog.json"

# create bobo3 session and clients
session = boto3.session.Session(region_name="eu-west-1")
ec2_client = session.client("ec2")
ec2 = session.resource("ec2")
security_group = ec2.SecurityGroup("id")


def get_security_group_id_with_least_rules():
    # Return id of a security group with a rule counnt less than 60. Error if all security group rule count is equal 60
    security_group_rules = get_security_group_rules()

    rule_count = int()
    security_group_id = None
    for rules in security_group_rules:
        print(
            "Security group "
            + rules["security_group_group_id"]
            + " has "
            + str(rules["security_group_rules_count"])
            + " rule(s)"
        )

        if rules["security_group_rules_count"] < 60:
            return rules["security_group_group_id"]

    sys.exit(
        "No space left for new rules in "
        + str(security_group_list)
        + ". Create another group"
    )


def authorize_ingress_rules(ip_list, security_group_rules):
    # Add security group rule if one does't already exist for each IP address in the Google IP address list

    rule_ip_list = list()
    for rules in security_group_rules:
        for rule in rules["security_group_rules"]:
            rule_ip_list.append(rule["CidrIpv4"])

    for ip_address in ip_list:
        if ip_address in rule_ip_list:
            print("A security group rule for " + ip_address + " already exists")
            continue

        security_group_id = get_security_group_id_with_least_rules()

        try:
            response = security_group.authorize_ingress(
                CidrIp=ip_address,
                FromPort=443,
                GroupId=security_group_id,
                IpProtocol="TCP",
                ToPort=443,
                DryRun=dry_run,
            )
            if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
                sys.exit(
                    "Error adding security group rule for "
                    + ip_address
                    + " to security group "
                    + security_group_id
                )
            else:
                print(
                    "Security group rule for "
                    + ip_address
                    + " has been added to security group "
                    + security_group_id
                )
        except Exception as e:
            print(
                e,
                "something went wrong adding security group rule for "
                + ip_address
                + " to security group "
                + security_group_id,
            )


def revoke_ingress_rules(ip_list, security_group_rules):
    # Remove rules from security groups if the IP address does not exist in Google IP list. Return nothing

    for rules in security_group_rules:
        for rule in rules["security_group_rules"]:
            if rule["CidrIpv4"] not in ip_list:
                security_group_rule_id = rule["SecurityGroupRuleId"]
                security_group_rule_cidr = rule["CidrIpv4"]
                security_group_id = rule["GroupId"]
                print(
                    security_group_rule_cidr
                    + " cannot be found in the Google IP address list. Removing rule "
                    + security_group_rule_id
                    + " from "
                    + security_group_rule_id
                )
                try:
                    response = security_group.revoke_ingress(
                        SecurityGroupRuleIds=[security_group_rule_id],
                        GroupId=security_group_id,
                        DryRun=dry_run,
                    )
                    if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
                        sys.exit(
                            "Error removing security group rule "
                            + security_group_rule_id
                            + " for "
                            + security_group_rule_cidr
                            + " from security group "
                            + security_group_id
                        )
                    else:
                        print(
                            "Security group rule "
                            + security_group_rule_id
                            + " for "
                            + security_group_rule_cidr
                            + " has been removed from security group "
                            + security_group_id
                        )
                except Exception as e:

                    print(
                        "something went wrong while removing security group rule "
                        + security_group_rule_id
                        + " containing "
                        + security_group_rule_cidr
                        + " from security group "
                        + security_group_id
                    )


def get_security_group_rules():
    # get aws security group ingress rules
    # return security group id, security rules list, and count of security rules.

    security_group_rules = list()

    for security_group in security_group_list:
        response = ec2_client.describe_security_group_rules(
            Filters=[
                {
                    "Name": "group-id",
                    "Values": [
                        security_group,
                    ],
                },
            ],
        )

        security_group_rules.append(
            {
                "security_group_group_id": security_group,
                "security_group_rules": response["SecurityGroupRules"],
                "security_group_rules_count": len(response["SecurityGroupRules"]),
            }
        )

    return security_group_rules


def get_ip_addresses_from_json(input_text):

    # Convert string input to json
    # Return list of IP addresses

    try:
        output_json = json.loads(input_text)
    except Exception as e:
        print(e)
        sys.exit("Something went while loading json")

    ip_list = []
    for item in output_json["prefixes"]:
        if "ipv4Prefix" in item:
            ip_list.append(item["ipv4Prefix"])

    if len(ip_list) < 1:
        sys.exit("IP list is empty")
    else:
        print(str(len(ip_list)) + " IP addresses found")
        return ip_list


def get_google_ip_list():
    # Get json doc container Google services IP addresses
    # Return list of IP addresses
    try:
        response = requests.get(google_endpoint)
        if response.status_code != 200:
            sys.exit("Bad response from google. Error code: " + response.status_code)
        else:
            return get_ip_addresses_from_json(response.text)
    except Exception as e:
        print(e)
        sys.exit(
            "Something went wrong while getting google endpoint " + google_endpoint
        )


def print_some_useful_info():
    print("security_group_list: " + str(security_group_list))
    print("google_endpoint: " + google_endpoint)
    print("dry_run: " + str(dry_run))


def main():

    print_some_useful_info()

    ip_list = get_google_ip_list()

    security_group_rules = get_security_group_rules()

    revoke_ingress_rules(ip_list, security_group_rules)

    security_group_rules = get_security_group_rules()

    authorize_ingress_rules(ip_list, security_group_rules)


if __name__ == "__main__":
    main()
