SpamSpotter
============

SpamSpotter is a script written in python which allows users to identify the source of outgoing spam on a linux server. This script also verifies whether 
the IP address of a server is blacklisted and if the 3-way DNS check is satisfied.

Compatability:

- Linux based OS
- PHP 5.3 and above
- python 2.4 and above


<h5>Download/Installation</h5>

Users can download the entire repository by using 'git clone' followed by the cloning URL above. Alternatively, use the following:

```wget https://raw.githubusercontent.com/fooltruth/SpamSpotter/master/SpamSpotter.py -O SpamSpotter.py```
```python SpamSpotter.py```

The execute bit (chmod +x SpamSpotter.py) can be added so that the script can be executed without calling python directly.

<h5>Application Usage</h5>

Here are instructions for Basic Usage of this script:

```SpamSpotter.py -a ```

Run SpamSpotter.py -h for a full list of available flags and operations

