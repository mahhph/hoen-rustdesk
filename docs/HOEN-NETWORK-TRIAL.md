# Historical Windows network trial

On November 5, 2026, a read-only trial rejected Lenovo's connection because the old Hoen policy required a specific Wi-Fi network and a Windows Private profile. The trial did not open a listener or test a desktop session. No network setting was changed.

The user subsequently clarified that the network path is not an access rule. A Hoen session may use any path, including local, VPN, Internet, or relay transport, provided its encrypted channel and mailbox identity/grant proof are verified. The old candidate-discovery script and trial example were removed because their pass/fail criteria no longer express the product requirement. The current runtime supports only its direct native TCP path; additional transports still need implementation and testing.
