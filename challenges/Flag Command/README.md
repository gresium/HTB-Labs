# Hack The Box – Flag Command (Full Step-by-Step Write-Up)

## Overview

This write-up documents the **exact sequence of actions** taken to solve the **Flag Command** challenge on Hack The Box.

This challenge is intentionally misleading. It looks like a text-based adventure where you must “choose the right path”, but in reality:

> **Dying is expected.  
> Progress is tracked server-side.  
> The secret is used AFTER the game ends.**

---

## Challenge Summary

- **Name:** Flag Command  
- **Category:** Web / Logic  
- **Release Date:** 31 May 2024  
- **Creator:** Xclow3n  

The challenge presents a fantasy adventure game with directional and narrative commands.

Almost **every choice kills you on purpose**.

---

## Step 1 – Starting the Game

When the game starts, you are prompted with directional commands such as:

HEAD NORTH
HEAD EAST
HEAD WEST
HEAD SOUTH

### Action Taken
HEAD NORTH


This advances the game to the next stage.

Other directions either:
- reset the description
- silently fail
- loop the story

---

## Step 2 – Deeper Into the Forest
You are then presented with a new set of commands, for example:
GO DEEPER INTO THE FOREST
FOLLOW A MYSTERIOUS PATH
CLIMB A TREE
TURN BACK

### Action Taken
GO DEEPER INTO THE FOREST


This moves the game forward.

⚠️ Commands must be:
- **ALL CAPS**
- **Exact spelling**
- **No extra spaces**

---

## Step 3 – Mid-Game Choices (Death Is Normal)

At later stages, you are given options such as:

ENTER A MAGICAL PORTAL
SWIM ACROSS A MYSTERIOUS LAKE
FOLLOW A SINGING SQUIRREL
BUILD A RAFT AND SAIL DOWNSTREAM


### What Happens Here

No matter which option you choose:

- You eventually **die**
- The game prints:
You died and couldn't escape the forest.


This is **intentional**.

👉 **At this point, the backend state matters more than the story text.**

---

## Step 4 – Finding the Secret (Critical Step)

While playing, browser **DevTools** were opened.

### Where the Secret Was Found

In **Network → XHR / Fetch → Response JSON**, an object was visible:

```json
secret: "Blip-blop, in a pickle with a hiccup! Shmigity-shmack"

Key points:
The secret is leaked client-side
It is not shown in the story
It is not the flag
It is not validated immediately
Step 5 – The Important Twist
Most people assume the secret must be entered before dying.
That is wrong.
The Correct Logic
You play the game
You die
The game still accepts input
After death, the secret is checked
This is why many attempts “look correct” but never return the flag.

Step 6 – Using the Secret (After Death)
After reaching the end and seeing the “You died” message, the secret was entered exactly as found:
Blip-blop, in a pickle with a hiccup! Shmigity-shmack

Rules:
Case-sensitive
No quotes
Exact punctuation
No extra spaces

Step 7 – Flag Revealed
After submitting the secret at the correct time, the game responded with:
You escaped the forest and won the game! Congratulations!

And printed the flag:
HTB{D3v3l0p3r_t0015_4r3_b35t_t0015_wh4t_d0_y0u_Th1nk??}

Why This Challenge Is Tricky
This challenge deliberately includes:
Silent failures
Identical network responses
Narrative misdirection
Late validation
Client-side secret leakage
It tests analysis and patience, not guessing.
Lessons Learned
Always inspect Network responses
Backend state ≠ story text
Dying does not mean failing
Never assume the first “success-looking” input is correct
Exact strings matter in CTFs

