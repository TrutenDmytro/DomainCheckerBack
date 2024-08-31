import { createClient } from "@supabase/supabase-js";
import express from "express";
import cors from "cors";
import axios from "axios";
import { Bot } from "grammy";
const app = express();
const port = process.env.PORT || 4000;

const supabaseURL = process.env.supabaseURL;
const supabaseKey = process.env.supabaseKey;
const virusTotalAPIKey = process.env.virusTotalAPIKey;
const telegramBotAPIKey = process.env.telegramBotAPIKey;

const supabase = createClient(supabaseURL, supabaseKey);
const bot = new Bot(telegramBotAPIKey);
let autoInterval;

const getURLID = (URL) => {
  return Buffer.from(URL)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
};

const getCurrentTimestamp = () => {
  const now = new Date();

  const year = now.getUTCFullYear();
  const month = String(now.getUTCMonth() + 1).padStart(2, "0");
  const day = String(now.getUTCDate()).padStart(2, "0");
  const hours = String(now.getUTCHours()).padStart(2, "0");
  const minutes = String(now.getUTCMinutes()).padStart(2, "0");
  const seconds = String(now.getUTCSeconds()).padStart(2, "0");

  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}+00`;
};

const scanURL = async (URL) => {
  const encodedParams = new URLSearchParams();
  encodedParams.set("url", URL);
  try {
    console.log("initialized scanURL");
    const response = await axios.post(
      `https://www.virustotal.com/api/v3/urls`,
      encodedParams,
      {
        headers: {
          accept: "application/json",
          "x-apikey": virusTotalAPIKey,
          "content-type": "application/x-www-form-urlencoded",
        },
      }
    );
  } catch (err) {
    console.log(err);
    throw err;
  }
};

const reanalyzeURL = async (URL) => {
  try {
    console.log("initialized reanalyzeURL");
    const response = await axios.post(
      `https://www.virustotal.com/api/v3/urls/${getURLID(URL)}/analyse`,
      null,
      {
        headers: {
          accept: "application/json",
          "content-type": "application/json",
          "x-apikey": virusTotalAPIKey,
        },
      }
    );
    return response.data.data.id;
  } catch (err) {
    console.log(err);
    throw err;
  }
};
const getURLAnalysis = async (reanalyzeID, domainID) => {
  console.log("initialized getURLAnalysis");
  let responseStatus = "queued";
  while (responseStatus !== "completed") {
    try {
      const response = await axios.get(
        `https://www.virustotal.com/api/v3/analyses/${reanalyzeID}`,

        {
          headers: {
            accept: "application/json",
            "content-type": "application/json",
            "x-apikey": virusTotalAPIKey,
          },
        }
      );
      responseStatus = response.data.data.attributes.status;

      if (response.data.data.attributes.status === "queued") {
        await new Promise((resolve) => setTimeout(resolve, 3000));
      } else if (response.data.data.attributes.status === "completed") {
        const { error } = await supabase
          .from("main")
          .update({
            analysis_result: response.data.data.attributes.stats,
            checked_at: getCurrentTimestamp(),
          })
          .eq("id", domainID);
        return response.data.data.attributes;
      }
    } catch (err) {
      console.log(err);
      throw err;
    }
  }
};

const autoCheckDomains = (data, delay = 20000) => {
  let index = 0;
  const scanningDelay = (ms) =>
    new Promise((resolve) => setTimeout(resolve, ms));

  autoInterval = setInterval(async () => {
    if (index < data.length) {
      try {
        const initialScanURL = await scanURL(data[index].url);
        await scanningDelay(2000);
        const reanalyzeID = await reanalyzeURL(data[index].url);
        const analysisResult = await getURLAnalysis(
          reanalyzeID,
          data[index].domainID
        );
        console.log(analysisResult);
        index++;
      } catch (err) {
        console.error("Error in /api/check-domain:", err);
      }
    } else {
      index = 0;
      console.log("Restarting array processing.");
    }
  }, delay);
};

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/api/get-domains", async (req, res) => {
  const { data, error } = await supabase.from("main").select();
  res.send(data);
});

app.get("/api/get-auto", async (req, res) => {
  const { data, error } = await supabase.from("auto").select();
  res.send(data);
});

app.post("/api/add-domain", async (req, res) => {
  try {
    const { status, statusText } = await supabase.from("main").insert(req.body);
    res.send({ status, statusText });
  } catch (err) {
    console.error("Error in /api/add-domain:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post("/api/manual-check", async (req, res) => {
  const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  try {
    const initialScanURL = await scanURL(req.body.url);
    await delay(2000);
    const reanalyzeID = await reanalyzeURL(req.body.url);
    const analysisResult = await getURLAnalysis(reanalyzeID, req.body.domainID);
    res.json(analysisResult);
  } catch (err) {
    console.error("Error in /api/check-domain:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post("/api/auto-check", async (req, res) => {
  if (req.body.is_auto_enabled) {
    const { data, error } = await supabase.from("main").select("domain, id");
    const updatedData = data.map((obj) => ({
      url: `https://${obj.domain}`,
      domainID: obj.id,
    }));
    autoCheckDomains(updatedData);
    console.log("initialized Autochecking");
  } else {
    clearInterval(autoInterval);
    console.log("Autochecking stopped");
  }
  await supabase
    .from("auto")
    .update({ is_auto_enabled: req.body.is_auto_enabled })
    .eq("id", 1);
});

app.delete("/api/delete-domain", async (req, res) => {
  try {
    const domainID = req.body.domainID;
    const response = await supabase.from("main").delete().eq("id", domainID);
    res.send(response);
  } catch (err) {
    console.error("Error in /api/delete-domain:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

app.listen(port, () => {
  console.log(`app listening on http://localhost:${port}/`);
});

bot.start();
