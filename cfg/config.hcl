Client "client1" {
    Required = true
    Interval = 5

    Deluge {
        URL = "http://127.0.0.1:8112/json"
        Password = "omg"
        MaxTorrents = 5
    }


    # Note the different syntax on Diskspace, GetUrl, and Process checks
    Diskspace = [
        {
            Partition = "/"
            MaxUsage = 90.0
        },
        {
            Partition = "/media/storage"
            MaxUsage = 100.0
        }
    ]

    # Comments are allowed
    #Loadavg {
    #    MaxLoad = 1.05
    #}
    
    GetUrl = [
        {
            Url = "http://google.com"
        },
        {
            Url = "https://some-url.com/health"
            ExpectedBody = "{\"alive\": true}"
        }
    ]
    
    Process = [
        {
            Path = "/a/process/with/specific/user"
            User = "aqtrans"
        },
        {
            Path = "aProcess"
        }
    ]

    Memory {
        MaxUsage = 10.0
    }

}


