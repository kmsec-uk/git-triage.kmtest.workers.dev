# Notes

### SOLAR SPIDER repo triage and hunt
retrieve github url

determine if fp:
	https://api.github.com/repos/Avia1010/Singapore/contents/
		If equal or more than 50% endswith zip it's a true positive

	query user api
	https://api.github.com/users/
		check when user was created (within last month?) - if yes it's TP
	

For each  users repo (https://api.github.com/users/Avia1010/repos):
	grab all zips from all repos if size is less than 300000
	https://api.github.com/repos/kppq/compliance/contents

SOLAR_SPIDER_zip triage:
	get sha256
	if not in VT:
		- submit to VT


http://github.com/kppq/compliance/raw/main/Wupos_Receipt_jpg.zip
http://raw.githubusercontent.com/kppq/compliance/main/Wupos_Receipt_jpg.zip