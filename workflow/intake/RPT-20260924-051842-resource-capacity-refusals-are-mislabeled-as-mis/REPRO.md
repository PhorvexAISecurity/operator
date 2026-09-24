# Preregistered source verification

Observed round17 audit has a complete exact event/policy/Pod join and misleading actionStatus. Reproduction criterion: actual nonempty-cover generator candidate with missing Service membership is excluded for resource-capacity but emitted as no-cover/recon-cover. Positive control: truly empty cover remains no-cover/recon-cover. Falsifier: baseline producer reports correctly typed resource-capacity or no such exclusion reaches the trace. Keep baseline/head tests and exact source pins. No new live stimulus for reproduction.
