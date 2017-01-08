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

### Edge
![image](https://cloud.githubusercontent.com/assets/1619279/20998446/b9315648-bcc2-11e6-9866-016725c8eaf8.png)

### Safari
![image](https://cloud.githubusercontent.com/assets/1619279/21753856/4f03b922-d5aa-11e6-8f63-c2bad2e54cd1.png)

### Firefox
![image](https://cloud.githubusercontent.com/assets/1619279/21236692/5f91c8a8-c2fc-11e6-8fe0-0594dcd464e2.png)

### Chrome
![image](https://cloud.githubusercontent.com/assets/1619279/21236656/354a37e2-c2fc-11e6-9669-9df1b989a187.png)
