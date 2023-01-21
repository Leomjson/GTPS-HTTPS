# Tutorial

## Building
Build in Visual studio 2022 in x64/release  (Download Visual Studio: https://visualstudio.microsoft.com/vs/)

![image](https://user-images.githubusercontent.com/89754898/213894062-05d15d9a-d6f9-4d0c-bd17-c69b3793332f.png)
![Capture](https://user-images.githubusercontent.com/89754898/213894208-c392011a-a4cd-41fb-83b2-2d0f657972f8.PNG)


## Configuring HTTPS accordingly
Change "127.0.0.1" to your VPS/VDS IP (found on the virtual machine information)

Change "55231" to the ENet Port (found in your GTPS project)

![image](https://user-images.githubusercontent.com/89754898/213894101-91c602c1-00ea-415e-b0b4-e9aec84d0f5c.png)

## Done Building?
Go to **x64/release** folder, then create a folder called **https** then another folder inside it called "connection". This folder will log connection information.
Then go back to **x64/release** folder and copy and paste the content(s) in **DLL** folder and paste it inside the **x64/release** folder.
Once you've done that run **https.exe**
