# Likely Viva Questions — Short Answers

**Q1. XXE kya hai?**
XML parser agar DOCTYPE/entity ko process karta hai aur external entity ko
resolve karta hai, to attacker us entity ko local file ya internal URL
par point kar sakta hai, aur parser woh data fetch kar ke leak kar deta hai.

**Q2. Out-of-band aur in-band detection mein farq?**
Out-of-band: apna khud ka listener banate hain; agar server us listener ko
hit kare, to yeh proof hai ke entity resolve hui. In-band: entity ka
result seedha HTTP response mein wapis aata hai (marker value dikhta hai).

**Q3. Parameter entity kyun use hoti hai?**
Kuch parsers general external entities (`&xxe;`) block kar dete hain lekin
internal DTD subset mein parameter entities (`%xxe;`) process kar lete
hain — yeh bypass ke liye use hoti hai jab plain variant kaam na kare.

**Q4. Error-based detection kya karta hai?**
Jaan-boojh kar ek undefined entity reference bhejte hain. Agar parser
DOCTYPE process kar raha ho to woh distinctive error message deta hai
(jaise `XMLSyntaxError`) jo batata hai ke parser entities ko evaluate
kar raha hai.

**Q5. Yeh tool asli websites pe kyun nahi chalana chahiye?**
Bina written permission ke kisi system ko probe karna Pakistan mein PECA
2016 ke under criminal offence hai. Isliye tool mein safety guard hai jo
non-local targets ko by default refuse karta hai.

**Q6. Fix kaise karte hain?**
XML parser mein DTD loading aur external entity resolution ko disable kar
dete hain (e.g. lxml mein `resolve_entities=False, load_dtd=False,
no_network=True`), ya defusedxml jaisi safe library use karte hain.

**Q7. Marker file real system file kyun nahi honi chahiye?**
Taake demonstration purely lab-controlled rahe — hum sirf apni banayi
hui harmless file ka content prove kar rahe hain, kisi sensitive/real
data ko touch nahi kar rahe.

**Q8. Listener kaise kaam karta hai?**
Python ke standard library `http.server` se ek chhota sa HTTP server
background thread mein chalta hai jo har incoming request ko time aur
source IP ke sath log karta hai.

**Q9. Tool kis Python libraries pe depend karta hai?**
Tool khud sirf standard library use karta hai (argparse, urllib,
http.server, ipaddress, socket). Sirf lab target apps (vulnerable/fixed)
demonstration ke liye Flask aur lxml use karte hain.

**Q10. Agar listener pe hit na aaye to kya hoga?**
Tool phir bhi in-band marker reflection aur error-based signatures check
karta hai — teen independent proofs mein se kisi ek ka positive aana
"VULNERABLE" verdict ke liye kaafi hai.
