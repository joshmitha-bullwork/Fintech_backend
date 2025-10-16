import express from "express";
import OpenAI from "openai";

const router = express.Router();
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY, // loaded from .env
});

router.post("/", async (req, res) => {
  try {
    const { prompt } = req.body;

    if (!prompt) {
      return res.status(400).json({ error: "Prompt is required" });
    }

  // ...
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini", // ✅ FIX: Change 'gpt-5' to a valid model
      messages: [{ role: "user", content: prompt }],
    });
// ...

    // send the text back to frontend
    res.json({ reply: completion.choices[0].message.content });
  } catch (error) {
    console.error("OpenAI Error:", error);
    res.status(500).json({ error: error.message });
  }
});

export default router;
