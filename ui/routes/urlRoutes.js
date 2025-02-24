const axios = require("axios"); // create and send web requests 
const express = require("express"); // serve those requests
const path = require("path");

const  router = express.Router();
const FASTAPI_URL = `${process.env.backend_protocol}://${process.env.backend_host}:${process.env.backend_port}`;

// accept and send the request and response to and from the client
router.get("/url-analysis", (req, res)=> {
    res.sendFile(path.join(__dirname, "..", "Template", "url_analysis.html"));
});

router.post("/analyze-url", async(req, res) =>{
    try{
        const {url} = req.body
        if(!url){
            return res.status(400).json({error: "IP address is required"});
        }
        const response = await axios.post(`${FASTAPI_URL}/analyze-url`, { url });
        res.json(response.data)
    }catch (error) {
        console.error("❌ Error analyzing URL:", error.message);

        const status = error.response ? error.response.status : 500;
        res.status(status).json({ error: "Error analyzing URL", details: error.message });
    }
});

module.exports = router;