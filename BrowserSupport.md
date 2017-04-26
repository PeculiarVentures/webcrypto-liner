# WebCrypto-Liner Browser Support
Each browser supports a different set of cryptographic algorithms and capabilities. WebCrypto-Liner tries to mask these differences with Javascript implementations of the various algorithms and datastructures. 

There are a few things to keep in mind:
- Wherever possible the native implementations are used,
- Some features, such as non-exportable keys, can not be implemented in Javascript,
- Size is a concern so although it is possible to implement some export formats we have decided not to,
- The Javascript implementation of algorithms is notably slower than their native counterparts,
- Lack of promise support on some browsersrequires promise polyfills which have their own issues.


### IE
![image](https://cloud.githubusercontent.com/assets/1619279/20998720/b0566818-bcc4-11e6-994b-a0943fcea527.png)

### Safari
![image](https://cloud.githubusercontent.com/assets/1619279/25404376/8893359c-29b4-11e7-8812-9e77c3fdc8cd.png)
![image](https://cloud.githubusercontent.com/assets/1619279/25404397/a3a1e2ac-29b4-11e7-8463-67ee5f7c713b.png)

### Edge
![image](https://cloud.githubusercontent.com/assets/1619279/25447872/a006560c-2a6b-11e7-893f-89a02bbfd209.png)

### Firefox
![image](https://cloud.githubusercontent.com/assets/1619279/25400303/f4577418-29a6-11e7-95e4-dfbb2da58811.png)

### Chrome
![image](https://cloud.githubusercontent.com/assets/1619279/25400294/e9fd08d4-29a6-11e7-994b-0a1c6ee5ed06.png)

