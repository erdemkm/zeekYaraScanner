# zeekYaraScanner
```
 ______          _     __   __                _____                                 
|___  /         | |    \ \ / /               /  ___|                                
   / /  ___  ___| | __  \ V /__ _ _ __ __ _  \ `--.  ___ __ _ _ __  _ __   ___ _ __ 
  / /  / _ \/ _ \ |/ /   \ // _` | '__/ _` |  `--. \/ __/ _` | '_ \| '_ \ / _ \ '__|
./ /__|  __/  __/   <    | | (_| | | | (_| | /\__/ / (_| (_| | | | | | | |  __/ |   
\_____/\___|\___|_|\_\   \_/\__,_|_|  \__,_| \____/ \___\__,_|_| |_|_| |_|\___|_|                                                               

```

## Description

This tool enables scanning files extracted by Zeek, a network traffic analyzer, with YARA rules to detect malicious content. YARA matching results are logged, and statistical analysis data can be obtained.
At the same time, by integrating with Picus, it is possible to simulate and analyze files matching YARA rules.

## Features

- File Scanning with YARA Rules
- YARA Matching Results Logging
- Statistical Analysis Data
- Integration with Picus
- Simulate with Picus

## Installation

Clone this repository and run following command;

```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

After installation, the values of the parameters in the config.py file should be set.

Config.py example;

```
### Yara Configuration
yara_rule_file = "rules/rule.yar" # Yara rule file path
yara_scan_dir = "/opt/zeek/extracted" # zeek file extract path
max_file_size_mb = 20 # max file size for files to scan
match_timeout = 60 # timeout in seconds
scan_file_time_limit = 1 # (if this variable is set 0, there is no time limit for zeek extracted file. It means scan files from last x hours.)
```

It can also be used by adding it to crontab. Crontab can be configured based on the 'scan_file_time_limit' value in the config file;

```
crontab -e
# Adding following line
0 * * * * python3 [project_path]/main.py
```

## Usage

```
usage: 
 ______          _     __   __                _____                                 
|___  /         | |    \ \ / /               /  ___|                                
   / /  ___  ___| | __  \ V /__ _ _ __ __ _  \ `--.  ___ __ _ _ __  _ __   ___ _ __ 
  / /  / _ \/ _ \ |/ /   \ // _` | '__/ _` |  `--. \/ __/ _` | '_ \| '_ \ / _ \ '__|
./ /__|  __/  __/   <    | | (_| | | | (_| | /\__/ / (_| (_| | | | | | | |  __/ |   
\_____/\___|\___|_|\_\   \_/\__,_|_|  \__,_| \____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                                                    
                                                                                    

       [-h] [-pcs] [-a]

optional arguments:
  -h, --help         show this help message and exit
  -pcs, --picus      Start Picus Analysis and fetch mitigation for malicious
                     files that matched yara rules.
  -a, --analyzelogs  Analyze alert logs and get detail statistics.
```

- Scan Zeek extracted files with YARA rules;

```
(venv) [root@zeektest zeekYara]# python main.py 
Start yara scanner for extracted zeek file...

match_id=MRqMibnrYD,type=yaraalert,msg=Yara match found on zeek extracted file.,file=/opt/zeek/extracted/HTTP-FjNHev36YNjrhd2uu3.exe,sha256=f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2,matchingrules=ExampleRule

Yara analysis done...

msg=Total yara rules match count for zeek extracted file:1
```

- Scan Zeek extracted files with YARA rules and get statistical analysis;

```
(venv) [root@zeektest zeekYara]# python main.py -a 
Start yara scanner for extracted zeek file...

match_id=bMcrUfWBsq,type=yaraalert,msg=Yara match found on zeek extracted file.,file=/opt/zeek/extracted/HTTP-FjNHev36YNjrhd2uu3.exe,sha256=f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2,matchingrules=ExampleRule

Yara analysis done...

msg=Total yara rules match count for zeek extracted file:1

########## Start Log Analysis ##########

---------- Total, Weekly, Daily Yara Match Count (group by sha256) ----------

Total yara match=4
Weekly yara match=3
Daily yara match=1

---------- Top 5 Yara Matches File ----------

+------------------------------------------------------------------+-------------+
|                               Hash                               | Match Count |
+------------------------------------------------------------------+-------------+
| f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2 |      22     |
| 52bf9809aa70dbc3fc8ee55dd96a58a7b85c45717a21e5f7c557a70b4ee07115 |      6      |
| 7ca363546736fea83c7185ffcef9cb35f28d5204c1a528f74e9881cd31f1223d |      3      |
| 53d40ef130ec04f1b0f8411dd2cda4dace9f0511f0fe319255ec6ce5faf30410 |      2      |
+------------------------------------------------------------------+-------------+
```

- Additional Picus simulation and analysis;

```
(venv) [root@zeektest zeekYara]# python main.py -pcs -a
Start yara scanner for extracted zeek file...

match_id=Ruq7TO7cdy,type=yaraalert,msg=Yara match found on zeek extracted file.,file=/opt/zeek/extracted/HTTP-FjNHev36YNjrhd2uu3.exe,sha256=f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2,matchingrules=ExampleRule

Yara analysis done...


Picus Assessment and fetch mitigation for matched malicious file...

match_id=Ruq7TO7cdy,type=picusinsecurealert,msg=Malicious file that matched yara rule is insecure on Picus.file=/opt/zeek/extracted/HTTP-FjNHev36YNjrhd2uu3.exe,sha256=f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2,matchingrules=ExampleRule,mitigation_id=xxx,mitigation_name=yyy,mitigation_vendor=Snort
match_id=Ruq7TO7cdy,type=picusinsecurealert,msg=Malicious file that matched yara rule is insecure on Picus.file=/opt/zeek/extracted/HTTP-FjNHev36YNjrhd2uu3.exe,sha256=f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2,matchingrules=ExampleRule,mitigation_id=xxx,mitigation_name=yyy,mitigation_vendor=SourceFire IPS

Picus processes done...

msg=Total yara rules match count for zeek extracted file:1

########## Start Log Analysis ##########

---------- Total, Weekly, Daily Yara Match Count (group by sha256) ----------

Total yara match=4
Weekly yara match=3
Daily yara match=1

---------- Top 5 Yara Matches File ----------

+------------------------------------------------------------------+-------------+
|                               Hash                               | Match Count |
+------------------------------------------------------------------+-------------+
| f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2 |      22     |
| 52bf9809aa70dbc3fc8ee55dd96a58a7b85c45717a21e5f7c557a70b4ee07115 |      6      |
| 7ca363546736fea83c7185ffcef9cb35f28d5204c1a528f74e9881cd31f1223d |      3      |
| 53d40ef130ec04f1b0f8411dd2cda4dace9f0511f0fe319255ec6ce5faf30410 |      2      |
+------------------------------------------------------------------+-------------+

---------- Total, Weekly, Daily Picus Insecure Result for Yara Matching (group by sha256) ----------

Total Insecure Picus match=2
Weekly Insecure Picus match=2
Daily Insecure Picus match=1

```

## Log Files

Under the 'logs' directory, there are alert logs and general logs. These logs can be forwarded to any SIEM (Security Information and Event Management) product for analysis.

## Yara Rule Files

A yara rule file can be stored under the "rules" directory. All yara rules should be in a single file.

## To-Do List

- Yara rules will be automatically fetched and updated from the specified sources

## License

This project is licensed under the MIT License. See the [License File](LICENSE) for details.
