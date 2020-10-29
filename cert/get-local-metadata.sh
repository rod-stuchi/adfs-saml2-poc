#! /bin/bash

curl -sk https://adfs.rods.local/FederationMetadata/2007-06/FederationMetadata.xml | xmllint --format - | bat
