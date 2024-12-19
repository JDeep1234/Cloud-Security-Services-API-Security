# Cloud-Security-Services-API-Security
Identify Cloud Services & Activities using AI/ML algorithms on Live Traffic and goal is to identify cloud service providers, identify the API endpoints, its activities, identify the order of API endpoints used by a user and get a pattern in them.  In order to achieve this, first it needs to discover API endpoints and discover the activities provided by them. These endpoints and activities are to be discovered through machine learning algorithms based on live traffic and for live traffic initially we could start with SASE public cloud service providers like DropBox, SalesForce, Google Docs, OneDrive, Box etc and later it could support other public and private API providers

## Setting Up AnyProxy

To set up AnyProxy for identifying and analyzing API endpoints and activities as described in your project, follow these steps:

### Step 1: Install AnyProxy
1. Install Node.js: AnyProxy requires Node.js. If you haven't installed it, download and install it from [Node.js](https://nodejs.org/).
2. Install AnyProxy: Use npm to install AnyProxy globally.
   ```bash
   npm install -g anyproxy
## Step 2: Configure AnyProxy  

**Note:** Step 2 is optional and is used only to save the decrypted traffic as a text file for further analysis. It can be skipped, and Step 3 can be implemented after Step 1.  

### 1. Create a Custom Rule File  

AnyProxy allows you to write custom rules to handle requests and responses. Create a JavaScript file (e.g., `customRule.js`) to define how you want to handle and analyze traffic.  
Customize the Service Name and URL Matching
### Set the Service Name:Replace 'YourServiceName' in the serviceName property with the actual name of the service you want to log (e.g., 'Salesforce').
### Update URL Matching Conditions:Modify the URL matching conditions in the activityType fields to reflect the actual endpoints of the service you are monitoring. 

For example, if you are logging Salesforce traffic, you might use:
## requestDetail.url.includes('login.salesforce.com')
## requestDetail.url.includes('DataImporterUploadServlet')
## requestDetail.url.includes('PrintableViewDownloadServlet')
**Example `customRule.js`:**  

```javascript  
const fs = require('fs');  

function logToFile(content) {  
  const logStream = fs.createWriteStream('./all_traffic_logs.json', { flags: 'a' });  
  logStream.write(JSON.stringify(content) + ',\n');  
  logStream.end();  
}  

module.exports = {  
  summary: 'Capture every single detail from the specified service traffic with tagging',  

  // Replace 'YourServiceName' with the actual service name you want to log  
  serviceName: 'YourServiceName',  

  *beforeSendRequest(requestDetail) {  
    const request = {  
      type: 'request',  
      url: requestDetail.url,  
      method: requestDetail.requestOptions?.method || 'UNKNOWN',  
      headers_Host: requestDetail.requestOptions.headers['Host'],  
      requestHeaders_Origin: requestDetail.requestOptions.headers['Origin'],  
      requestHeaders_Content_Type: requestDetail.requestOptions.headers['Content-Type'],  
      requestHeaders_Referer: requestDetail.requestOptions.headers['Referer'] || '',  
      requestHeaders_Accept: requestDetail.requestOptions.headers['Accept'] || '',  
      requestHeaders_Sec_Fetch_Mode: requestDetail.requestOptions.headers['Sec-Fetch-Mode'] || '',  
      service: this.serviceName, // Use the service name defined above  
      activityType: (requestDetail.url.includes('login.yourservice.com')) ? 'Login' :  
                    (requestDetail.url.includes('UploadServlet') ||  
                     requestDetail.url.includes('createJobDefinition')) ? 'Upload' :  
                    (requestDetail.url.includes('DownloadServlet') ||  
                     requestDetail.url.includes('exportDialog')) ? 'Download' : 'Unknown'  
    };  

    logToFile(request);  
    return null;  
  },  

  *beforeSendResponse(requestDetail, responseDetail) {  
    const response = {  
      type: 'response',  
      url: requestDetail.url,  
      method: requestDetail.requestOptions?.method || 'UNKNOWN',  
      headers_Host: requestDetail.url,  
      responseHeaders_Content_Type: responseDetail.response.header['Content-Type'] || '',  
      responseHeaders_Content_Disposition: responseDetail.response.header['Content-Disposition'] || '',  
      responseHeaders_Content_Encoding: responseDetail.response.header['Content-Encoding'] || '',  
      service: this.serviceName, // Use the service name defined above  
      activityType: (requestDetail.url.includes('DownloadServlet') ||  
                     requestDetail.url.includes('exportDialog')) ? 'Download' :  
                    (requestDetail.url.includes('UploadServlet') ||  
                     requestDetail.url.includes('createJobDefinition')) ? 'Upload' : 'Unknown'  
    };  

    logToFile(response);  
    return null;  
  }  
};
```  

### 2. Start AnyProxy with Your Custom Rule  

Run AnyProxy with your custom rule file to start capturing traffic.  

Use the following command:  

`anyproxy --rule customRule.js`


### Step 3: Set Up Your System to Use the Proxy  

1. **Configure Proxy Settings:** Set up your browser or system to route traffic through AnyProxy.  
   - **Manual Proxy Configuration:**  
     After clicking on "Open Proxy," the above setting appears, and the IP address of the local machine needs to be entered along with the port as `8001`.

     
![image](https://github.com/user-attachments/assets/b574dd63-95fe-450e-95aa-c39c1fc6d5e5)


![image](https://github.com/user-attachments/assets/3a3d022f-0e46-4e81-aaee-2b396b4dce8d)


![image](https://github.com/user-attachments/assets/1f64cae4-4c01-46ea-bec7-5ebc05752e01)

 Then, open the Chrome browser and type `localhost:8002`, and the above page appears.  


    

   Now configure the AnyProxy root certificate in the Chrome browser:  
   - Download the AnyProxy root CA certificate from the AnyProxy UI.  
   - Import the root certificate to Chrome: `chrome://settings/?search=manage+certificates`.  

### Step 4: Capture and Analyze Traffic  

Start AnyProxy with the following command:  

```bash  
anyproxy --port 8001 --rule customRule.js  # if rule is used  
```  

or  

```bash  
anyproxy --intercept  # without any rule  
```

### Step 5: Convert Captured Traffic to CSV for Analysis  

The previous script captures HTTP traffic and logs Saas service in a JSON format. This JSON file contains detailed information about each request and response, including headers, URLs, methods, and activity types. The following Python script reads this JSON log file and converts the captured traffic into a CSV file for easier analysis.  

#### Step 5.1: Ensure Python Environment is Set Up  

1. **Install Python**: Make sure you have Python installed on your machine. You can download it from [python.org](https://www.python.org/downloads/).  
2. **Install Required Libraries**: The provided code uses built-in libraries (`json`, `csv`, `os`), so no additional installations are necessary.  

#### Step 5.2: Create the Python Script  

1. **Create a New Python File**:  
   - Create a new file named `process_logs.py` in the same directory where your `all_traffic_logs.json` file is located.  

2. **Copy the Provided Code**:  
   - Copy the following code into `process_logs.py`:  

   ```python  
   import json  
   import csv  
   import os  

   def read_logs(log_file):  
       with open(log_file, 'r', encoding='utf-8') as f:  
           logs = f.readlines()  
       return [json.loads(log.strip(',\n')) for log in logs if log.strip(',\n')]  

   def process_logs(logs):  
       processed_logs = []  
       for log in logs:  
           # Filter to include only GET and POST methods and Salesforce URLs  
           if log.get('method') in ['GET', 'POST'] and 'salesforce.com' in log.get('url', ''):  
               processed_log = {  
                   'headers_Host': log.get('headers_Host', ''),  
                   'url': log.get('url', ''),  
                   'method': log.get('method', 'UNKNOWN'),  
                   'requestHeaders_Origin': log.get('requestHeaders_Origin', ''),  
                   'requestHeaders_Content_Type': log.get('requestHeaders_Content_Type', ''),  
                   'responseHeaders_Content_Type': log.get('responseHeaders_Content_Type', ''),  
                   'responseHeaders_Content_Disposition': log.get('responseHeaders_Content_Disposition', ''),  
                   'responseHeaders_Content_Encoding': log.get('responseHeaders_Content_Encoding', ''),  
                   'requestHeaders_Referer': log.get('requestHeaders_Referer', ''),  
                   'requestHeaders_Accept': log.get('requestHeaders_Accept', ''),  
                   'requestHeaders_Sec_Fetch_Mode': log.get('requestHeaders_Sec_Fetch_Mode', ''),  
                   'service': log.get('service', 'Salesforce'),  
                   'activityType': log.get('activityType', 'Unknown')  
               }  
               processed_logs.append(processed_log)  
       return processed_logs  

   def write_to_csv(processed_logs, output_file):  
       headers = [  
           'headers_Host', 'url', 'method', 'requestHeaders_Origin',  
           'requestHeaders_Content_Type', 'responseHeaders_Content_Type',  
           'requestHeaders_Referer', 'requestHeaders_Accept',  
           'responseHeaders_Content_Disposition', 'responseHeaders_Content_Encoding',  
           'requestHeaders_Sec_Fetch_Mode', 'service', 'activityType'  
       ]  

       # Remove existing file if it exists to avoid appending to old data  
       if os.path.exists(output_file):  
           os.remove(output_file)  

       with open(output_file, mode='w', newline='', encoding='utf-8') as file:  
           writer = csv.DictWriter(file, fieldnames=headers)  
           writer.writeheader()  

           for log in processed_logs:  
               row = {key: log.get(key, '') for key in headers}  
               writer.writerow(row)  

   # Paths to input and output files  
   logs = read_logs('./all_traffic_logs.json')  
   processed_logs = process_logs(logs)  
   write_to_csv(processed_logs, './all_traffic_dataset.csv')  

   print("Dataset created: all_traffic_dataset.csv")

### Step 5.3:Adjust the URL Filtering
If you want to capture traffic from a different service, modify the condition in the process_logs function:

#### Replace 'yourservice.com' with the actual domain of the service you are interested in.

 ```python 
if log.get('method') in ['GET', 'POST'] and 'yourservice.com' in log.get('url', ''):

### Step 4: Run the Python Script

#### Open a Terminal or Command Prompt:
1. Navigate to the directory where your `process_logs.py` file is located.

#### Run the Script:
2. Execute the script using Python:

   ```bash
   python process_logs.py
   ```

#### Check for Output:
3. After running the script, you should see a message indicating that the dataset has been created:

   ```yaml
   Dataset created: all_traffic_dataset.csv
   ```
#### Verify the CSV File:
4. Open `all_traffic_dataset.csv` in a spreadsheet application (like Excel) or a text editor to review the processed logs.


## AI/ML For Analysis of the Endpoints

### Identifying API Endpoint Signatures:

To classify an API endpoint or an activity, there would be certain signatures within a set of packets. These signatures could vary among them and hence need to be identified. Below is an example for a DropBox application and its activities:

| Service Name | Identified Activities |
|--------------|------------------------|
| DropBox      | Login                 |
|              | Download              |
|              | Upload                |



### Features for Classification and Prediction of Activity Type

The following features are used to classify and predict activity types based on packet signatures:

1. **headers_Host**: 
   - Contains the domain name, which is often a strong indicator of the service being accessed. For example, "www.dropbox.com" is unique to Dropbox, making it a reliable feature to identify the SaaS platform being used.
2. **URL**: 
   - Provides detailed information about the endpoint being accessed, which can help classify specific activities such as login, download, or upload based on URL patterns.
3. **requestHeaders_Origin**:
   - Reveals the origin domain for cross-origin requests, allowing correlation between the request and its originating application or page.
4. **requestHeaders_Content-Type / headers_Content-Type**: 
   - Indicates the nature of the request payload. For instance, JSON often relates to configuration or metadata, while multipart/form-data typically corresponds to file uploads.
5. **responseHeaders_Content-Type**:
   - Shows the format of the response data, which helps in identifying the activity type, such as receiving a file or metadata.
6. **requestHeaders_Referer / headers_Referer**:
   - Provides the source of the request, which can be linked to specific activities like downloading a file from a shared link or navigating between pages.
7. **requestHeaders_Accept / headers_Accept**:
   - Specifies the content types expected in the response, helping to predict activities such as downloading files or fetching JSON metadata.
8. **responseHeaders_Content-Disposition**:
   - Commonly used in file downloads. It specifies whether the content should be displayed inline in the browser or treated as an attachment. The filename included here can further validate download activities.
9. **responseHeaders_Content-Encoding**:
   - Indicates if the response data is compressed, which is often seen in download scenarios to optimize data transfer.
10. **requestHeaders_Sec-Fetch-Mode**:
    - Identifies the mode of the request, such as "navigate" for full page loads or "cors" for API interactions, helping to differentiate between user-driven actions and background API calls.






