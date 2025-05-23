from typing import Any, Dict, List, Text
from rasa_sdk import Action, Tracker
from rasa_sdk.events import SlotSet
from rasa_sdk.executor import CollectingDispatcher
import re
import requests
from transformers import T5Tokenizer, T5ForConditionalGeneration
from urllib.parse import urlparse
from difflib import SequenceMatcher

# Load T5 model once for efficiency
tokenizer = T5Tokenizer.from_pretrained("t5-small")
model = T5ForConditionalGeneration.from_pretrained("t5-small")

VIRUSTOTAL_API_KEY = "9445c8faf2ad351dfab7642538e7bc03ac505c3838ae41f8ca306df55712816b"

def extract_urls(text: Text) -> List[Text]:
    pattern = re.compile(
        r"(https?://[^\s]+|www\.[^\s]+|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})(/[^\s]*)?"
    )
    return [m[0] for m in pattern.findall(text)]

def is_lookalike(domain: Text, legit_domains: List[Text] = None) -> bool:
    if legit_domains is None:
        legit_domains = [
            "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
            "twitter.com", "instagram.com", "linkedin.com", "netflix.com", "reddit.com",
            "yahoo.com", "bing.com", "ebay.com", "paypal.com", "apple.com",
            "microsoft.com", "github.com", "stackoverflow.com", "medium.com", "tumblr.com",
            "pinterest.com", "quora.com", "dropbox.com", "drive.google.com", "docs.google.com",
            "office.com", "slack.com", "zoom.us", "skype.com", "discord.com",
            "spotify.com", "soundcloud.com", "vimeo.com", "twitch.tv", "hulu.com",
            "disneyplus.com", "primevideo.com", "hbo.com", "cnn.com", "bbc.com",
            "nytimes.com", "theguardian.com", "forbes.com", "washingtonpost.com", "reuters.com",
            "bloomberg.com", "huffpost.com", "tripadvisor.com", "booking.com", "airbnb.com",
            "uber.com", "lyft.com", "expedia.com", "kayak.com", "yelp.com",
            "indeed.com", "glassdoor.com", "monster.com", "coursera.org", "edx.org",
            "udemy.com", "khanacademy.org", "ted.com", "pixabay.com", "unsplash.com",
            "flickr.com", "wellsfargo.com", "bankofamerica.com", "chase.com", "citibank.com",
            "schwab.com", "vanguard.com", "coinbase.com", "stripe.com", "alipay.com",
            "wechat.com", "alibaba.com", "taobao.com", "jd.com", "flipkart.com",
            "etsy.com", "walmart.com", "target.com", "bestbuy.com", "nike.com",
            "adobe.com", "salesforce.com", "atlassian.com", "jira.atlassian.com", "confluence.atlassian.com",
            "docker.com", "npmjs.com", "hashicorp.com", "wordpress.com", "wix.com",
            "squarespace.com", "mail.yahoo.com", "outlook.com", "live.com"
        ]

    for legit in legit_domains:
        ratio = SequenceMatcher(None, domain.lower(), legit.lower()).ratio()
        if 0.75 < ratio < 1.0:
            return True
    return False



class ActionCheckLinkSafety(Action):
    def name(self) -> Text:
        return "action_check_link_safety"

    def run(
        self,
        dispatcher: CollectingDispatcher,
        tracker: Tracker,
        domain: Dict[Text, Any],
    ) -> List[Dict[Text, Any]]:

        user_input = tracker.latest_message.get("text", "")
        urls = extract_urls(user_input)

        # 1️⃣ If no URL, prompt for one and exit
        if not urls:
            dispatcher.utter_message(text=(
                "🚫 I couldn’t find a link in your message. "
                "Please include a URL or domain, e.g., example.com"
            ))
            return []

        # 2️⃣ Normalize and store the first URL
        url_to_check = urls[0]
        if not url_to_check.startswith("http"):
            url_to_check = "http://" + url_to_check

        # 3️⃣ Run T5 phishing analysis
        clean_input = user_input.replace("analyze:", "").strip()
        t5_prompt = f"analyze: {clean_input}"
        input_ids = tokenizer(t5_prompt, return_tensors="pt").input_ids
        output_ids = model.generate(input_ids, max_length=64)
        t5_result = tokenizer.decode(output_ids[0], skip_special_tokens=True)

        # 4️⃣ VirusTotal check
        vt_result = "🔍 Could not get VirusTotal response."
        try:
            res = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
                data={"url": url_to_check}
            )
            res.raise_for_status()
            scan_id = res.json()["data"]["id"]
            rep = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{scan_id}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY}
            )
            rep.raise_for_status()
            stats = rep.json()["data"]["attributes"]["stats"]
            if stats.get("malicious", 0) > 0:
                vt_result = "⚠️ VirusTotal flagged this link as potentially malicious."
            else:
                vt_result = "✅ VirusTotal did not flag the link as dangerous."
        except Exception as e:
            vt_result = f"⚠️ Error checking VirusTotal: {e}"

        # 5️⃣ Heuristic flags
        parsed = urlparse(url_to_check)
        domain_name = parsed.netloc or parsed.path.split("/")[0]
        lookalike_flag = is_lookalike(domain_name)
        pattern_flag = (
            any(kw in domain_name.lower() for kw in ["login","verify","secure","update","free","bonus"])  
            or any(domain_name.lower().endswith(tld) for tld in [".xyz",".ly",".tk",".ru",".top",".buzz"])
        )

        if lookalike_flag:
            vt_result += " ⚠️ This domain resembles a trusted site."
        if pattern_flag:
            vt_result += " 🚩 Suspicious pattern detected in domain name."

        # 6️⃣ Build advice
        lower_t5 = t5_result.lower()
        if "bank" in lower_t5:
            advice = "🚫 A bank would never send sensitive links. This is likely a scam."
        elif "account" in lower_t5 and "compromised" in lower_t5:
            advice = "⚠️ This may be from a compromised account trying to phish you."
        elif "reward" in lower_t5:
            advice = "🎁 This looks like a fake reward scam. Don’t trust it."
        elif lookalike_flag:
            advice = "⚠️ The domain mimics a trusted brand—be extra cautious."
        elif pattern_flag:
            advice = "🚩 This domain includes high-risk terms or uncommon TLDs. Treat it as potentially dangerous."
        else:
            advice = "🔍 Be cautious. This could be phishing. Don’t click unless you’re sure."

        # 📍 helper to wrap text in a colored <span>
        def color(text: str, c: str) -> str:
            return f"<span style='color:{c};'>{text}</span>"

        # decide if advice is a “warning”
        is_warning = any(icon in advice for icon in ("⚠️", "🚩"))
        advice_color = "red" if is_warning else "black"

        # 7️⃣ Final HTML message with bubble wrapper
        final_html = (
            f"<div class='bot-bubble'>"
            f"🧠 <strong>Phishing Technique Identified</strong>: {color(t5_result, 'black')}<br/><br/>"
            f"🔗 <strong>URL Check</strong>: {color(vt_result, 'black')}<br/><br/>"
            f"🛠 <strong>Advice</strong>: {color(advice, advice_color)}"
            f"</div>"
        )
        dispatcher.utter_message(text=final_html, disable_sanitization=True)

        # 8️⃣ Store the last link for follow-up
        return [SlotSet("last_link", domain_name)]
