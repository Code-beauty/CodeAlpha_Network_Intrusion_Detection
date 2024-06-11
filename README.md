# CodeAlpha_Network_Intrusion_Detection
Network Intrusion Detection System  Develop a network-based intrusion detection system using Suricata. Set up rules and alerts to identify and respond to suspicious network activity. You can even visualize the detected attacks.

Here are the steps (Kali Linux):

Install Suricata:
sudo apt-get install suricata

Update the Emerging Threats Open Ruleset:
sudo suricata-update

This command downloads and installs the latest version of the ruleset to the default location (/var/lib/suricata/rules/).

Configure Suricata:
sudo nano /etc/suricata/suricata.yaml

Important Configurations:

home-net: Replace with your actual internal network subnet.
rule-files: This section defines the location of your Suricata rule files. You can find the default rules in (etc/suricata/rules/). You define your own rules and add the path at this section.
Start Suricata With Specific Configurations:
sudo suricata -c suricata.yaml -s rulespath -i interface

Starts Suricata: The suricata command initiates the Suricata program.
Configuration file: -c suricata.yaml specifies the configuration file, which holds settings like network interfaces and rule paths.
Rule file: -s rulespath defines the rules file, could be the default rules file which is (/var/lib/suricata/rules/suricata.rules) or custom rules file.
Network interface: -i interface indicates the network interface from which Suricata will capture traffic for analysis.
Test & Verify Suricata:
sudo tail -f /var/log/suricata/fast.log

Suricata Rule Writing Basics
Suricata relies on rules to detect suspicious network activity. Writing effective rules requires understanding their structure and components. Here's a breakdown of the basics:

Structure:

A Suricata rule consists of three primary sections:

Action: Defines what happens when the rule matches traffic. This typically involves actions like logging, alerting, or dropping packets.
Header: Specifies the conditions that the traffic must meet to trigger the rule. This includes defining parameters like protocol, IP addresses, ports, and direction of the traffic flow.
Rule Options: Further refine the rule's behavior using various options like content matching, payload analysis, and timeouts. Let's explore each section in detail:
1. Action:
alert: Logs the event with a specific severity level (e.g., low, medium, high).
log: Logs the event without assigning a severity level.
drop: Blocks the offending packet.
chain: Triggers another rule for further analysis. Example:
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Potential web server exploit attempt"; flow:to_server; classtype:attack-analysis;)

2. Header:
protocol: Specifies the network protocol (e.g., tcp, udp, icmp).
source: Defines the source IP address or network using CIDR notation or keywords like $HOME_NET for your internal network.
destination: Defines the destination IP address or network using similar options.
source_port: Specifies the source port or port range.
destination_port: Specifies the destination port or port range.
direction: Defines the direction of traffic flow (e.g., -> for forward, <-> for bi-directional).
3. Rule Options:
msg: Defines a custom message to be logged when the rule triggers.
flow: Defines the direction of traffic flow within the rule (e.g., to_server, from_server).
classtype: Assigns a classification category to the detected event.
