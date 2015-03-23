# Introduction #

The masterkey inside self-issued cards is neither used (while importing) nor generated (while issuing). It is needed to generate a RP-dependent PPID which is compatible to Microsoft CardSpace.

Without this the xmldap id selector for Firefox CAN not be compatible to CardSpace.


# Details #

We need code that generates the RSA keys from the masterkey as described in section "8.4.1. Processing rules" from the document "Identity Selector Interoperability Profile V1.0" http://download.microsoft.com/download/1/1/a/11ac6505-e4c0-4e05-987c-6f1d31855cd2/identity-selector-interop-profile-v1.pdf