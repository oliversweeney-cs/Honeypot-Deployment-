# Honeypot-Deployment

## Honeypot Setup and Installation

## Objective

This project aimed to set up and install a honeypot in a cloud environment to detect and log unauthorized access attempts. A honeypot is a security mechanism that mimics a vulnerable system, enticing attackers and allowing security teams to gather information on their behaviour. This project provides hands-on experience in deploying a honeypot, monitoring intruder activity, and understanding attack patterns.

## Skills Learned

- In-depth knowledge of honeypot technology and its role in network security.
- Proficiency in setting up and configuring a honeypot environment.
- Experience in monitoring and logging attack activity.
- Improved understanding of common attack vectors and intruder behaviour.
- Ability to analyze and interpret logs for security insights.

## Tools Used

- T-Pot Honeypot Platform: A multipurpose honeypot solution integrating various honeypot services to log and detect unauthorized access.
- Kibana: Visualization and dashboard creation tool used to analyze the data collected by T-Pot.
- Elastic Stack: To centralize and manage the log data from the honeypot.
- Suricata: An intrusion detection system (IDS) integrated with T-Pot to monitor network traffic and detect malicious activities.
- SSH Clients: Used to simulate attacks and interact with the honeypot.

## Steps
### Step 1: Installing the Honeypot Environment

The first step was to spin up a virtual machine using a cloud-based server. I used a service called Vultr to deploy an Ubuntu 24.04 server. T-Pot was selected as the platform because it can integrate multiple honeypot solutions (Cowrie, Dionaea, Honeytrap, etc.). This multipurpose setup enables the system to mimic various vulnerable services, attracting various attacks. Once T-Pot was chosen, I followed the documentation to install T-Pot onto the Ubuntu virtual machine. Finally, using the Vultr platform, a firewall rule was implemented for the internet-facing virtual machine that only allowed my IP address to access the backend of T-Pot and then allowed the rest of the internet access to the rest of the honeypot. 

Ref 1: Screenshot of Vultr/Machine hosting the T-Pot server and Firewall Rules
![image](https://github.com/user-attachments/assets/80c5fe48-87f7-48cd-8f77-b2a2f82ee946)
![image](https://github.com/user-attachments/assets/224b849f-f8ed-412e-aef8-3f3e22c6f7cb)


### Step 2: Configuring the Honeypot

The honeypot was configured to capture interactions with multiple types of services, including SSH, HTTP, and SMB. Each honeypot module (such as Cowrie for SSH and Dionaea for malware) monitors and logs different types of interactions. This multi-layered approach captures various attack vectors and methods used by attackers.


### Step 3: Monitoring and Analyzing Attack Data from T-Pot

After deploying the honeypot, data from the different services was aggregated and visualized using Kibana on the Elastic Stack. The following screenshots show the various attacks detected and the insights derived from the logs.
General Attack Insights:

The total number of detected attacks was 152,938, with 116,557 coming from the Sentrypeer honeypot. This indicates a high level of probing activity aimed at SSH services.

Ref 3: Screenshot of overall attack statistics, honeypot distribution, and attack map
![image](https://github.com/user-attachments/assets/e7a32a2e-13fd-4ed5-b1f6-e4bb4a5fb8e2)
![image](https://github.com/user-attachments/assets/8b98a4d5-b4d2-4cb1-801f-2f643dbed607)

#### Attack by Honeypot and Service:

The dashboard's bar chart indicates that Sentrypeer and Ddospot were the most targeted honeypots. SSH brute force attacks were common, especially on services mimicked by Sentrypeer. Other honeypots like Honeytrap and Dionaea also recorded significant activity, which suggests attackers were probing for various vulnerable services, such as HTTP and malware distribution points.

Ref 4: Screenshot of honeypot attack distribution by service
![image](https://github.com/user-attachments/assets/a0afff0f-c58d-4756-bc8a-f3f31720cc62)

#### Attack Patterns Over Time:

The timeline of attacks shows clear peaks in attack activity, with a surge at 14:30 on October 10, 2024. During this time, 48,357 attacks were recorded, with 282 unique source IPs. When that time is compared with the graph showing the attacks by destination ports, the consistent pattern of attacks targeting port 5060 suggests attempts to exploit SIP vulnerabilities.

Ref 5: Screenshot of attack timeline and port distribution
![image](https://github.com/user-attachments/assets/a8aad7a3-6761-4ad2-ac4b-52957364c679)
![image](https://github.com/user-attachments/assets/796719e0-e1ca-4580-9605-cee7b713bab0)

### Step 4: Insights from Attacker Behavior
#### Attacks by Country and IP Reputation:

Most attacks originated from Romania, followed by the United States and France. Analysis of the reputation of the attacking IP addresses indicates that most were classified as known attackers or mass scanners. This aligns with the global trend of distributed scanning operations targeting exposed services.

Ref 6: Screenshot of attack source countries and IP reputation analysis
![image](https://github.com/user-attachments/assets/b5cd9162-76af-4ca9-b2e0-f193f58b4f21)
![image](https://github.com/user-attachments/assets/eb014af2-3eba-44b8-96e0-670d74370c13)

#### Username and Password Analysis:

The honeypot captured a variety of username and password combinations used in brute force attempts. The most common username was root, and many default credentials, such as admin and 123456, were used. The password cloud also highlights the prevalence of simple, easily guessable passwords like admin and 1234.

Ref 7: Screenshot of username and password tag clouds
![image](https://github.com/user-attachments/assets/e5c1ae76-c525-4f6d-a2c7-15fd4e8e8f53)

### Step 5: Conclusion and Insights

The deployment of T-Pot as a honeypot solution provided valuable insights into attackers' methods and behaviour when targeting exposed services. Throughout the monitoring period, the honeypot captured a wide range of attack vectors, giving us a deeper understanding of attack patterns, the geographical distribution of threats, and common vulnerabilities exploited by malicious actors.

#### Key Observations and Attack Patterns:

The honeypot detected 152,938 attacks, mainly targeting Sentrypeer and Ddospot, primarily simulating SSH and denial-of-service (DoS) vulnerabilities. This highlights attackers' persistent focus on SSH services, likely driven by the widespread use of SSH for remote management and the opportunity for privilege escalation through weak authentication practices. The volume of attacks against these honeypots indicates that many attackers are leveraging automated tools to scan the internet for vulnerable SSH endpoints and using brute-force methods to gain access.

Further analysis revealed that the attacks came in bursts, with significant spikes in activity during certain periods, such as at 14:30 on October 10, 2024, when over 48,357 attacks were recorded within a short window. This suggests using botnets or coordinated attack campaigns, where attackers deploy distributed systems to probe multiple targets simultaneously. The high number of unique source IP addresses (282) during these spikes reinforces this observation, showing how attackers often use decentralised infrastructures to evade detection and maximise their chances of success.

#### Geographical Distribution of Attacks:

One of the most revealing aspects of the data was the geographical distribution of attack sources. The honeypot registered significant activity from Romania, the United States, and France. Romania, in particular, stood out with an unusually high volume of attacks, which may indicate the presence of many compromised systems within the country being used for malicious activities. Alternatively, attackers could leverage IP spoofing or proxy services to mask their true location, making Romania a hotspot for cyber threats.

The presence of attacks from the United States and France is consistent with global trends. Both countries have significant IT infrastructures and are often targeted by cybercriminals due to the large number of servers and IoT devices that could be vulnerable to exploitation. It's also important to note that many of these attacks might originate from hosts in these regions rather than being directly controlled by attackers based there.

#### Common Ports and Services:

A closer look at the destination port analysis highlights the popularity of certain services among attackers. The top targeted port was 5060, associated with Session Initiation Protocol (SIP), widely used in VoIP communications. This suggests that attackers were attempting to exploit vulnerabilities in VoIP services, potentially for eavesdropping, denial-of-service attacks, or unauthorised access to voice communication systems. Other frequently targeted ports included 53 (DNS), 445 (SMB), and 23 (Telnet), all of which are well-known for being exploited in various types of attacks, including data exfiltration, lateral movement, and service disruptions.

The presence of port 445 (SMB) in the analysis highlights attackers' ongoing attempts to exploit vulnerabilities such as EternalBlue, which was famously used in the WannaCry ransomware attacks. Despite available patches, many organisations fail to secure SMB services, leaving them vulnerable to exploitation.

#### Username and Password Analysis:

One of the key objectives of a honeypot is to capture the credentials attackers attempt to use during brute-force attacks. In this case, the honeypot successfully logged a variety of username and password combinations, providing insights into the tactics used by attackers to gain unauthorised access. Unsurprisingly, the most commonly used username was root, as attackers often target the superuser account to gain maximum control over a system. Other frequently targeted usernames included admin, test, and guest, commonly found on poorly configured systems or IoT devices with default credentials.

The password analysis revealed the widespread use of weak passwords such as admin, 123456, and password. These passwords continue to be used in brute-force attacks due to their simplicity and the fact that many organisations or devices still employ default or weak authentication mechanisms. The presence of more complex passwords, such as 1qaz@WSX and OxhlwSG8, also suggests that some attackers use dictionary attacks that include simple and moderately complex password combinations.

#### Insights into Attacker Infrastructure:

Analysing attacker IP addresses and ASNs (Autonomous System Numbers) offers insights into the infrastructure attackers use. Many attacks originated from known IP addresses linked to malicious activity, including some from Unmanaged Ltd and DEDIOUTLET-NETWORK. Using IP addresses linked to hosting services or poorly managed networks indicates that attackers often use infrastructure to launch their attacks, whether through compromised servers or services that don't enforce strict security policies.
Interestingly, the Suricata alerts linked to these IP addresses showed repeated attempts to exploit SMB vulnerabilities. This indicates that attackers are actively probing for outdated and vulnerable SMB services to execute remote code or exfiltrate sensitive data.

#### Role of Automated Attack Tools and Botnets:
The consistent presence of attacks aimed at common services like SSH, SMB, and Telnet suggests that attackers use automated tools or botnets to scan for vulnerable systems en masse. This allows them to quickly identify exposed services, attempt brute-force logins, and deploy exploits across many targets. The honeypot's ability to detect and log these attacks highlights the importance of maintaining visibility into all network activity, as attackers often rely on automation to discover weaknesses before security teams respond.

#### Recommendations for Defense:

- Monitor and analyse honeypot data regularly: The insights gathered from this project underscore the value of honeypots in detecting and understanding attacker behaviour. Organisations should consider deploying honeypots as part of their security strategy to gain visibility into attack trends and test their defences.

- Implement robust authentication mechanisms: The prevalence of brute-force attempts on services like SSH and SMB highlights the need for strong passwords and multi-factor authentication. Turning off root login for SSH and enforcing password complexity policies can mitigate the risk of unauthorised access.
Patch vulnerable services: Services like SMB and Telnet remain prime targets for attackers, many of whom exploit known vulnerabilities in unpatched systems. Regular patching and turning off unnecessary services can significantly reduce the attack surface.

- Leverage threat intelligence: By analysing the IP addresses and ASNs linked to attacks, organisations can enrich their security operations with threat intelligence feeds, enabling them to block known malicious actors and proactively defend against new threats.

