# WebInvestigation - Network Forensics CTF by CyberDefender
<h1>WebInvestigation</h1> WebInvestigation is a Network Forensics CTF within CyberDefender which offers hands-on practical experience for SOC Anaylst. 

<br><h2>Scenario: </h2> 
You are a cybersecurity analyst working in the Security Operations Center (SOC) of BookWorld, an expansive online bookstore renowned for its vast selection of literature. BookWorld prides itself on providing a seamless and secure shopping experience for book enthusiasts around the globe. Recently, you've been tasked with reinforcing the company's cybersecurity posture, monitoring network traffic, and ensuring that the digital environment remains safe from threats.

Late one evening, an automated alert is triggered by an unusual spike in database queries and server resource usage, indicating potential malicious activity. This anomaly raises concerns about the integrity of BookWorld's customer data and internal systems, prompting an immediate and thorough investigation.

As the lead analyst on this case, you are required to analyze the network traffic to uncover the nature of the suspicious activity. Your objectives include identifying the attack vector, assessing the scope of any potential data breach, and determining if the attacker gained further access to BookWorld's internal systems.

<h3>Securirty tools used for this CTF and their purpose</h3> 
  -WireShark (Network Analysis and PCAP (Packet Capture)) 
  
  <br>-NetworkMiner (Network Anaylsis)

  -VM (Kali Linux)

  -IP Lookup ( https://www.whatismyip.com/ip-address-lookup/ )

<h4>Question 1.</h4> 
<b>By knowing the attacker's IP, we can analyze all logs and actions related to that IP and determine the extent of the attack, the duration of the attack, and the techniques used. Can you provide the attacker's IP?</b>


<br><h4>Approach:</h4> We are looking for the IP of the attacker. Wireshark is a great network analysis tool that provides packets showing both source and destination IP's traversing data throughout the network. In the scenrio above we are provided with information that states,<i> "an automated alert is triggered by an unusual spike in database queries and server resource usage, indicating potential malicious activity."</i> Given this information we should begin looking for unusal amounts of packets coming to and/or from an IP address not within our network. 

<h3>Steps</h3> 
<b>Step 1</b>
After downloading the packet capture from CyberDefender and inputing the provided password to unzip the file we will open the file in WireShark.

<br><b>Step 2</b>
There are 88,862 packets being displayed in this PCAP, instead of manually searching for an anomally we can click on the <b>Statistics</b> tab at the top of our WireShark tool... from there, we naviagate to the <b>Conversation</b> tab (not pictured).![WebStatsTab](https://github.com/TEvans-Developer/WebInvest.-CTF/assets/140648793/a498f17e-706b-416d-be8b-1ce334c0f5bc)

<b>Step 3</b> In <b>Conversation</b> we will navigate to the IPv4 tab. We then can see there are 88,484 of our 88,862 PCAPs being sent from an IP address <i>111.224.250.131</i> in the <b>Address A</b> column to one of the IP address in our network. This unusual amount of network traffic leads us to believe this is the source of the anomaly and will need further investigation.![WebConversation](https://github.com/TEvans-Developer/WebInvest.-CTF/assets/140648793/e88a2c57-cb48-42c3-946a-71195aa36706)


<b>Answer:</b> <i>111.224.250.131</i>
<hr>

<h4>Question 2.</h4>
<b>If the geographical origin of an IP address is known to be from a region that has no business or expected traffic with our network, this can be an indicator of a targeted attack. Can you determine the origin city of the attacker?</b>

<h4>Approach:</h4> We want to further ensure our suspicion that the anomaly is coming from a source that is <b>NOT</b> in our network and being that the IP is not in our network there is also a chance the IP address is not in our region. There are many open source IP address Lookups that allow us to see the region as well as other information about the potential threat actor. We will utilize https://www.whatismyip.com/ip-address-lookup/ for our research.

<h3>Steps</h3> 
<b>Step 1</b> Visit https://www.whatismyip.com/ip-address-lookup/ or any <b>Secure</b> IP address Lookup website of your choice.

<br><b>Step 2 </b> Input your potential threat actors IP address, <i>111.224.250.131</i>.We can now see the threat actors region is located in <i>Shijiazhuang</i>,China.

<br>![IPRegionLookUp](https://github.com/TEvans-Developer/WebInvest.-CTF/assets/140648793/07edfa29-0a3a-4cdb-84d0-83fe094a54e1)


<br><b>Answer:</b><i>Shijiazhuang</i>
<hr>

<h4>Question 3.</h4>
<b>Identifying the exploited script allows security teams to understand exactly which vulnerability was used in the attack. This knowledge is critical for finding the appropriate patch or workaround to close the security gap and prevent future exploitation. Can you provide the vulnerable script name?</b>

<h4>Approach</h4>
We want to know how the threat actor exploited the system. This well help us understand vulnerabilites in the system and ways to mitigate them in the future. Being that there are a large number of packets being sent to the threat actors IP address we can assume they are making request to a server in our network. WireShark has a utility that allows us to analyze these request. We will take this approach for our analysis. 

<h3>Steps</h3>

<b>Step 1</b>
Navigate to the <b>Statistics</b> tab on the top of WireShark and from there we will navigate to <b>HTTP</b> at the bottom of the listed items.Hover over <b>HTTP</b>, the option <b> Request</b> will then appear. Click this option. 

<br><b>Step 2</b>
A list of all HTTP request made during the PCAP will show here. Below we observe multiple <i>search.php</i> request were made.
<br><i><b>* search.php is a script that handles search functionality on a website which are common in SQL Injections*</i></b>
<br>![WebHTTPRequest](https://github.com/TEvans-Developer/WebInvest.-CTF/assets/140648793/9b0e379b-4405-4b15-977a-04bc9b70e4b5)

<br><b>Answer:</b><i>search.php</i>
<hr>

<h4>Question 4.</h4>
<b>Establishing the timeline of an attack, starting from the initial exploitation attempt, What's the complete request URI of the first SQLi attempt by the attacker?</b>

<h4>Approach</h4>
Understanding that a URI (Uniform Resource Identifier) is a string of characters used to identify a name or resource on the internet. "GET" request are a type of call that is made to servers to get information from the server. Taking into account of this information and some knowledge of SQL Injections that are made such as <b>1=1</b> we can utilize WireSharks filter options, <b>Find Packet</b> and <b>Display Filter</b> to find the time in which the threat actor made their first SQL Injection request. 

<h3>Steps</h3>

<b>Step 1</b>
In the <b>Display Filter</b> bar we want to input our threat actors IP address with this syntax <i>ip.addr == 111.224.250.131</i>.

<br><b>Step 2</b>
At the top of WireShark we will see the <b>Edit</b> tab. After clicking this tab we will click the <b>Find Packet</b> option which will allow for another filter to appear.This <b>Find Packet</b> filter allows us to enter specific strings we want to find within the packets of WireShark. We will enter a common SQL Injection <i>1=1</i> in this filter. 

<br><b>Step 3</b>
After the filters are inputed we can see frame 357 is highlighted with the threat actors IP address as the source.There is also a span of information that has the <b>1=1</b> within it. 

<br><b>Step 4</b> 
We can also navigate to the bottom left portion of our WireShark tool to see the packet details. In the packet details we will navigate to the bottom of the listed layers where it says <b>Hypertext Transfer Protocol</b>. HTTP expands and we will see a the "Get" request URI that was made with the search.php script including the SQL injection <b>1=1</b>

<br>![WebURIAttempt](https://github.com/TEvans-Developer/WebInvest.-CTF/assets/140648793/e52844c1-c76d-4ee8-99d9-8136874dfe9e)

<h3>**Disregard the highlighted "Go" in screen shot**</h3>



<br><b>Answer:</b><i>/search.php?search=book%20and%201=1;%20--%20-</i>
<hr>

<h4>Question 5.</h4>
<b>Can you provide the complete request URI that was used to read the web server available databases?</b>

<h4>Approach</h4>
We want to find the threat actors successful attempt that was made. Knowing that codes in the range of 200 is a "successful" code that is returned to the person(s) when making a request to a database and that a common database type such as <i>MySQL</i> is used we can use this information to better filter our searches for our analysis. 

<h3>Steps</h3>

<b>Step 1</b>
In the filter bar we will input our threat actors ip address. We will then inlcude the "&&" operator which stands for "and" ; appeneding "http.response.code == 200" to it. The entire filter should look something like this. 
<br>
<b>ip.addr == 111.224.250.131 && http.response.code == 200</b>

<br><b>Step 2</b>
We want to find the response of 200 that is correlated to the MySQL database. We will go to <b>Edit > Find Packet </b> then enter "mysql" into the filter as a string. 

<br><b>Step 3</b>
After inputting our filters we will be able to navigate to the packet details in the HTTP portion to find the full URI request made. This finding is similar to that of the analysis in question 4. 
<br>![FullURI1](https://github.com/TEvans-Developer/WebInvest.-CTF/assets/140648793/f85544cb-c22b-4f47-9ba9-42577f4f9228)


<br><b>Step 4 </b>
To dive a bit deeper we can get more context of the URI request by following the http stream. In order to do so we right click the highlighted packet in the packet list, navigate down to the <b>follow</b> option, then click the <b>HTTP Stream</b>. This will show us the TCP stream request and responses made between our server and the threat actor for this respected packet.
![FullURI2](https://github.com/TEvans-Developer/WebInvest.-CTF/assets/140648793/1c0ce75e-0981-4a8d-a76b-e6a4be79421c)


<br><b>Answer:</b><i>/search.php?search=book%27%20UNION%20ALL%20SELECT%20NULL%2CCONCAT%280x7178766271%2CJSON_ARRAYAGG%28CONCAT_WS%280x7a76676a636b%2Cschema_name%29%29%2C0x7176706a71%29%20FROM%20INFORMATION_SCHEMA.SCHEMATA--%20-</i>
<hr>

<h4>Question 6.</h4>
<b>Assessing the impact of the breach and data access is crucial, including the potential harm to the organization's reputation. What's the table name containing the website users data?</b>

<h4>Approach</h4>
We want to understand our data,how it is set up ,what potential user data that is vulnerable and what the threat actor can see. We could use NetworkMiner to assist with our analysis here. 

<h3>Steps</h3>

<b>Step 1</b>
We can open our PCAP in Network Miner. We then can click the files tab and input "search.php" in our filter keyword in our Network Miner tool. Upon researching for unusually large files that were transfer we can see on frame 1622 that 1,125B of data were being transfer to the destination IP of our threat actor and the ephermeral destination port  assigned to them , port <b>38848</b>. We can also see in the packet details that there are names of users and information in the packet bytes.
<br>![WebUserDatabaseNetworkMiner](https://github.com/TEvans-Developer/WebInvest.-CTF/assets/140648793/3b4a7aed-5b5f-4277-a4c5-26cd47e5b0b7)


<br><b>Step 2</b>
After finding the port information we now can go back to WireShark and input the threat actors IP and the destination port in our display filter for further analysis. <b>ip.addr == 111.224.250.131 && tcp.dstport == 38848</b>

<br><b>Step 3</b>
We will then follow the <b>HTTP Stream</b> of frame 1624 to find our database <i>bookworld_db.customers</i>.

<br>![WebUserDatabase](https://github.com/TEvans-Developer/WebInvest.-CTF/assets/140648793/6be675b4-7a49-406f-8932-176103280cd6)


<br><b>Answer:</b><i>customers</i>
<hr>

<h4>Question 7.</h4>
<b>The website directories hidden from the public could serve as an unauthorized access point or contain sensitive functionalities not intended for public access. Can you provide name of the directory discovered by the attacker?</b>

<h4>Approach</h4>
We must understand that hidden directories are often sources of information only visible to admin with certain privileges due the sensitive data and functionalitites. Using prior questions we know that being able to follow HTTP Streams will help us analyize what request the threat actor made and which ones were successful as far as manipulating admin credentials to view private data.

<h3>Steps</h3>

<b>Step 1</b>
In the display filter we should input our HTTP response code of 200 and our Find packet filter should say "admin" as a string within our "packet details" to find all occurances where admin is mentioned.
<br>![WebAdmin](https://github.com/TEvans-Developer/WebInvest.-CTF/assets/140648793/56b0c85e-2f5c-40fd-971a-d6fad4467500)


<br><b>Step 2</b>
We then can follow the HTTP Stream to see in-depth more about the request and how the threat actor got to the admin directory or simply go to packet detail on the lower left side of WireShark to see the same information.  
<br>![AdminFollow](https://github.com/TEvans-Developer/WebInvest.-CTF/assets/140648793/e6c93f0d-bd14-40fa-b458-8c0a8f5e1aed)



<br><b>Answer:</b><i>/admin/</i>
<hr>

<h4>Question 8.</h4>
<b>Knowing which credentials were used allows us to determine the extent of account compromise. What's the credentials used by the attacker for logging in?</b>

<h4>Approach</h4>
Understanding that WireShark provides filtering methods that allow you to pin point and follow HTTP streams for request made to a server. Understand that a request to login into a system requires a POST request and if the request is successful the threat actor then has access to private data.

<h3>Steps</h3>

<b>Step 1</b>
We should input into our display filter "http.request.method==POST" which will give us back 5 different POST request made by the threat actor in a brute force attempt to access the admin portal.
<br>** (optional) - We can use Network Miner as it provides an option to see credentials** 

<br><b>Step 2</b>
Upon analysis and following the HTTP Stream we find that packet 88,699 has information that the threat actor made an successful log in attempt due to a default login credential that was not removed from the system. 
UserName:<i>admin</i> and password:<i>admin123!</i> 

<br>![WebLoggedIn](https://github.com/TEvans-Developer/WebInvest.-CTF/assets/140648793/44e1445f-8403-4e93-bcae-2895d4c4fa86)


<br><b>Answer:</b><i>admin:admin123!</i>
<hr>

<h4>Question 9.</h4>
<b>We need to determine if the attacker gained further access or control on our web server. What's the name of the malicious script uploaded by the attacker?</b>

<h4>Approach</h4>
We must understand that some malicious script was "uploaded" by the attacker to aid him in exploiting and finding vulnerabilities. Due to common naming convictions using the keyword "upload" in WireShark could help us find what the malicious script was.

<h3>Steps</h3>

<b>Step 1</b>
As done in the previous questions we will input into our display filter "http.request.method == POST" with our Find Packet filter "upload" for packet details.
<br><b>** POST is a type of HTTP request that is used to send data to a server to create or update a resource. POST request are used for logins **</b>

<br><b>Step 2</b>
From here we are able to see the filename of the malicious script that was uploaded in our packet details on lower left.
<br>![WebScript](https://github.com/TEvans-Developer/WebInvest.-CTF/assets/140648793/2749b3bc-111e-4982-82f3-945cad66cbc8)


<br><b>Answer:</b><i>Nvri2vhp.php</i>

<h2> Report</h2>
<br> It seems that our threat actors purpose was to infiltrate the network to gain access to sensitive data and upload a malicious script.
<h3>Tactics</h3>
<br> Credential access, Exfiltration, Discovery
<h3>Techniques</h3>
<br>SQL Injection,Using Credentials,Brute Force,Exploiting unpatched vulnerabilities
<h3>Procedure</h3>
The threat actor was able to infiltrate sensitive user data by using SQL injections to reach the admin directory and customer database. Once inside the admin directory the threat actor used brute force to gain access to admin login due to default credential that were not removed. The threat actor was then able to upload a malicious script called, <i>Nvei2vhp.php</i> which could further cause damages to the system, allow for lateral movement, cause DDOS, gain access to sensitive data and more.

<h4> Ways to mitigate</h4>
<br>- Better management of user credentials by removing default credentials and implementing MFA with other verification methods.
<br>- Utilize least privilege policy.
<br>- Implement better coding so that SQL injections are not possible by using parameterized queries, stored procedures, escape user input and etc.
<br>- Implement IDS, IPS (Snort) and SIEM (Splunk, ELK, etc.) for better monitoring and alerts of anomalies.
<br>- Implement web based Firewalls for SQL injections.
<br>- Regular patches and network monitoring.
<br>- Implement using HTTPS with other encryption methods to lower the risk of information being transfered as plain text.




