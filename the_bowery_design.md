The Bowery. Security Software Design Document: Distributed Agent and Whispering Protocol

Project name: The Bowery  
Author: Julien Vehent

This document outlines the detailed design specifications for a new security software product. This product is defined by its distributed architecture and novel communication methodology, intended to provide advanced endpoint detection and response (EDR) capabilities.

1\. Project Goal and Core Differentiator

The goal is to build a distributed agent that will be installed on local machines. This agent is tasked with monitoring the behavior of those machines in order to detect malicious activity.

The key property and difference of this solution is that, instead of trying to make decisions autonomously, it will employ a **whispering protocol** to exchange information with its neighbors. In essence, this system functions as a neighborhood watch. In that exchange, each local endpoint will attempt to determine if the activity they are seeing is expected in the environment where they are currently operating, or if it could be malicious.

2\. Core Agent Design and Functionality

The software will be implemented as a core agent that operates at a very low level on the operating system.

2.1 Low-Level Visibility and Instrumentation

* **Initial Platform:** The initial implementation will start with Linux.  
* **Kernel Integration:** The core agent should leverage eBPF filter and, in particular, the Kernel Security Instrumentation framework (KRSI).  
* **Monitoring Scope:** The agent must have visibility into all system calls, process execution, network connections, file operations, and so on that are happening on the system. This comprehensive visibility is essential for deep behavioral monitoring.

2.2 Local Activity Analysis

* **LLM Integration:** The local agent will leverage an LLM model that must be embedded directly into the agent to analyze its local activity. Consider using gemma-4 and implement it in a way that easily allows models to be swapped out. We also want to control cpu/gpu/ram allocations carefully using configurable limits.  
* **Anomalous Surfacing:** The purpose of the LLM analysis is to surface anything that is "out of the ordinary".  
* **Baseline Management:** A database will also be necessary to keep track of normal and expected behavior on the machine. This database will identify anything that might be different from the baseline of the activity. For example, new processes, unusual binaries, rare system calls, network connections to unusual IPs, etc.

2.3 The Whispering Protocol

The communication protocol defines how agents validate anomalous activity.

* **Trigger:** Communication is triggered when something anomalous and potentially malicious surfaces on the local system.  
* **Initiation:** The local agent will attempt to communicate with other nodes on the network.  
* **Local discovery:** broadcast network protocol and other techniques are used to find other agents on the local network segment.  
* **Trust and Handshake:**  
  * Nodes must perform a handshake and use encryption.  
  * Nodes will use their local signing keys with fingerprinting to ensure that they are always talking to the same trustworthy nodes.  
  * **Initial Setup Trust:** It is assumed that when a new agent is created, the environment is trusted. A handshake is performed, and the agent will keep track of one of its neighbors. The initial setup is assumed to be free of malicious activity, allowing the agent to trust the initial configuration.  
* **Whispering Mechanism:** Once the handshake is established and the node has the fingerprints of all of its neighbors, it can whisper to them in an encrypted fashion.  
* **Query:** The whisper is a private inquiry, asking if a given piece of activity that the local agent has noticed on its system has also been observed in those neighborhood systems.

2.4 Response and Action Capabilities

If the local agent determines that the activity it observed has **not** been observed in the neighborhood systems, it can decide to take one or more forms of action:

* Completely killing the process.  
* Killing the network connection.  
* Blocking file access.  
* Sending a notification to an operator.

2.5 Design and Implementation Constraints

* **Weight:** Agents must be designed to be as lightweight as possible.  
* **Implementation Language:** The chosen implementation language must allow for:  
  * Close control over resource consumption.  
  * Implementation of low-level Kernel modules with KRSI.  
  * Provision of as much security and safety as possible.  
* **Autonomy:** The deployed fleet of agents should be able to monitor their own activity, talk to each other, and figure out if something malicious or suspicious is happening, all without any sort of human intervention.

3\. Operator and Backend Infrastructure

There is no backend service. Instead, an operator can use a trusted signing key to issue a message to one agent, which then broadcast that message through the whispering protocol.

3.2 Command and Control (C2) Interface

* **Messaging Protocol:** The operator must have a way to send encrypted and signed messages to local agents to ask questions.  
* **Query Functionality:** Operators should be able to request specific information about one or multiple local systems. This capability is similar to the security software OSQuery, and consideration should be given to using that framework as a library.  
* **Investigation:** The C2 interface must allow the operator to run large-scale queries and investigations and potentially take mitigative actions. Those queries are propagated through the whispering network and results returned back to the operator.  
* **Operator Interface Preference:**  
  * A command-line interface (CLI) is preferred for operators, as it allows them to issue and sign commands being sent over to the agents.

4\. Use Cases

1. Permanent monitoring in the background, alerting operators of suspicious activity.  
2. Threat hunting: running investigation queries through the whispering network to detect binaries with specific file hashes, processes with given names, etc.  
3. On-demand detection: sending a script to an agent to run a very specific detection related to an ongoing attack or a vulnerability. For example, we might want to monitor specific syscalls for 72 hours following the release of a kernel vulnerability.