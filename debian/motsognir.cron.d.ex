#
# Regular cron jobs for the motsognir package
#
0 4	* * *	root	[ -x /usr/bin/motsognir_maintenance ] && /usr/bin/motsognir_maintenance
