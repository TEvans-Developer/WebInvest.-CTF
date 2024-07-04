# WebInvestigation - CTF by CyberDefender
<b>WebInvestigation </b> is a CTF within CyberDefender which allows hands-on practical experience for SOC Anaylst. 

<h2>Scenario: </h2> 
You are a cybersecurity analyst working in the Security Operations Center (SOC) of BookWorld, an expansive online bookstore renowned for its vast selection of literature. BookWorld prides itself on providing a seamless and secure shopping experience for book enthusiasts around the globe. Recently, you've been tasked with reinforcing the company's cybersecurity posture, monitoring network traffic, and ensuring that the digital environment remains safe from threats.

Late one evening, an automated alert is triggered by an unusual spike in database queries and server resource usage, indicating potential malicious activity. This anomaly raises concerns about the integrity of BookWorld's customer data and internal systems, prompting an immediate and thorough investigation.

As the lead analyst on this case, you are required to analyze the network traffic to uncover the nature of the suspicious activity. Your objectives include identifying the attack vector, assessing the scope of any potential data breach, and determining if the attacker gained further access to BookWorld's internal systems.

<h3>Securirty tools used for this CTF and their purposes</h3> 
  -WireShark (Network Analysis and PCAP (Packet Capture)) 
  
  -NetworkMiner (Network Anaylsis)

<h4>Question 1.</h4> 
<b>By knowing the attacker's IP, we can analyze all logs and actions related to that IP and determine the extent of the attack, the duration of the attack, and the techniques used. Can you provide the attacker's IP?</b>


<br><h4>Approach:</h4> We are looking for the IP of the attacker. Wireshark is the a great network analysis tool that provides packets showing both source and destination IP's traversing data throughout the network. In the scenrio above we are provided with information that states,<i> "an automated alert is triggered by an unusual spike in database queries and server resource usage, indicating potential malicious activity."</i> Given this information we should begin looking for unusal amounts of packets coming to and/or from an IP address not within our network. 

<h3>Steps</h3> 
<b>Step 1</b>
After downloading the packetcapture from CyberDefender and inputing the provided password to unzip the file we will open the file in WireShark.

<br><b>Step 2</b>
There are 88,862 packets being displayed in this PCAP, instead of manually searching for an anomally we can click on the <b> Statistics</b> tab at the top of our WireShark tool; from there, we naviagate to the <b>Conversation</b> tab(not pictured).![WebStatsTab](https://github.com/TEvans-Developer/WebInvest.-CTF/assets/140648793/a498f17e-706b-416d-be8b-1ce334c0f5bc)

<b>Step 3</b> In the Conversation we will navigate to the IPv4 tab. We then can see there are 88,484 of our 88,862 PCAP being sent from an IP address <i>111.224.250.131</i> in the <b>Address A</b> column to one of the IP address in our network. This unusal amount of network traffic leads us to believe this is the source of the anomaly and will need further investigation.![WebConversation](https://github.com/TEvans-Developer/WebInvest.-CTF/assets/140648793/e88a2c57-cb48-42c3-946a-71195aa36706)


<b>Answer:</b> <i>111.224.250.131</i>
<hr>

<h4>Question 2.</h4>
<b>If the geographical origin of an IP address is known to be from a region that has no business or expected traffic with our network, this can be an indicator of a targeted attack. Can you determine the origin city of the attacker?</b>

<h4>Approach:</h4> We want to further ensure our suspicion that the anomaly is comming from a source that is <b>NOT</b> in our network and being that the IP is not in our network there is also a chance the IP address is not in our region. There are many opensource IP address Lookups that allow us to see the region as well as other information about the potential threat actor. We will utilize https://www.whatismyip.com/ip-address-lookup/ for our research.

<h3>Steps</h3> 
<b>Step 1</b> Visit https://www.whatismyip.com/ip-address-lookup/ or any <b>Secure</b> IP address Lookup website of your choice.

<br><b>Step 2 </b> Input your potential threat actors IP address, <i>111.224.250.131</i>.We can now see the threat actors region is located in <i>Shijiazhuang</i>,China.

<br>![IPRegionLookUp](https://github.com/TEvans-Developer/WebInvest.-CTF/assets/140648793/07edfa29-0a3a-4cdb-84d0-83fe094a54e1)


<br><b>Answer:</b><i>Shijiazhuang</i>
<hr>


