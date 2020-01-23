
# treadm1ll
You don't need to be as fast as [lightspeed](https://www.synacktiv.com/posts/exploit/lightspeed-a-race-for-an-iosmacos-sandbox-escape.html), but a run on a treadm1ll surely doesn't hurt.

---
Since i'm now busy with other stuff and likely not gonna come back to this
here is my unfinished exploit:

- works up to 11.4.1
- gets you tfp0
- incomplete/missing cleanup, will probably panic on exit


Offsets hardcoded for:
 ```Darwin Kernel Version 17.4.0: Fri Dec  8 19:35:52 PST 2017; root:xnu-4570.40.9~1/RELEASE_ARM64_S5L8960X```   
Get your own if you wanna run it on something else ;)




PS: exploit uses userland derefs, so it won't work with PAN  
only for phones with headphone jack

---

A great writeup by Luca Moro (johncool) on the bug can be found here:  
[https://www.synacktiv.com/posts/exploit/lightspeed-a-race-for-an-iosmacos-sandbox-escape.html](https://www.synacktiv.com/posts/exploit/lightspeed-a-race-for-an-iosmacos-sandbox-escape.html)
