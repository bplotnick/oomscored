# oomscored
## OOM score daemon

oomscored solves the problem of automatically adjusting the "OOM score" for processes in Linux.

## Background

Currently, when a linux system runs out of memory, the out-of-memory killer (OOM killer) will kick in and score processes based on a set of heuristics. The processes with the highest score then gets killed.  Sometimes the user would like to bias the OOM killer against or for killing certain processes, and this is accomplished via the oom_score_adj tunable (see section 3.1 of [this](https://www.kernel.org/doc/Documentation/filesystems/proc.txt) for more technical details).

The problem is that this must be done on a per-processes basis, and there is no way to set general policies. So, for example, I can’t say “user plotnick should always have a higher score and user root should have a lower score” or “processes named ipython should be killed more readily than other processes”. This is where oomscored comes in.

## oomscored

oomscored is a daemon process that monitors all processes spawned, killed, and modified on a system, and will apply oom_score_adj tunings to the processes according to a set of rules specified by the user. The design is influenced by [cgred](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Resource_Management_Guide/sec-Moving_a_Process_to_a_Control_Group.html#The_cgred_Service), which does a similar job, but deals with cgroups (and it is written in a different language)

## Caveats

oomscored is _very_ alpha. Do not use this in production.

There is a dependency on the open_source proc_events [library](https://github.com/dbrandt/proc_events) (with in turn is alpha)

