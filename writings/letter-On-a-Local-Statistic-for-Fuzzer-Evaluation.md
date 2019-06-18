(Note: this is more a letter / manuscript expressing thoughts on a possible area of investigation)

## On the Possible Use of a Local Statistic in Fuzzer Evaluation

Reading [Manes] and looking at recent conference accepted papers and talks,
it is clear that research and development of fuzzers and fuzzing methodologies
continues to be active. While many developments seem to be taking the form of 
the application of machine learning, biological systems theory, and SMT solvers, 
there are a number of researchers investing significant time into the improvement 
of how we evaluate fuzzers and how to compare fuzzing methodologies. While many of
these new techniques sound exciting, implying researchers need to keep up,
we should remind the reader that a number of recent and important bugs 
are found by the simplest of fuzzers [VidCon], so choose your own adventure!

There are a few reasons for the focus on evaluation; one in particular is due to
an ugly trend of incomplete testing data, statistically insignificant data used,
and the lack of available code for reproduction. At least two papers have been
released that we believe will help to improve these issues; the [Hicks] paper 
and the [Berger] replicability in CS checklist. They are both needed and should
help to improve paper and talk acceptance criteria - well worth taking the time
to read and reflect on. Another reason for the focus on evaluation is the continued 
question of what makes a good testsuite. Determining a good testsuite should only 
help give credence to a statistically significant comparison of fuzzers and so it 
is an important quest. An even more recent paper by Böhme notes that a "security researcher
should be able to systematically assess and quantify the inherent uncertainty", thus
he puts out a "Call for Systematic Statistics" in order to build a statistical
framework suitable for fuzz-based software testing [Böhme]. Each of these efforts is
calling for increased rigor in our analysis of fuzzers instead of relying on
human experience and/or low numbers of trials.                                        

A popular statistic for evaluation that people consider is the number of bugs found in a given 
test suite, perhaps under some condition(s) (e.g., 24hr time-boxed, average of
30 runs, etc). And we think this is a reasonable measuring stick, when adhered
to and when the test suite is "good enough". In our mind, we start to think of this
value as a type of global statistic. That is, it is from a holistic viewpoint of how
well a fuzzer has done on a given code base with certain seed(s), time frame,
and hardware. Afterall, it's the bugs we are after, no? Further, other global statistics 
might be overall code coverage and overall branch coverage.

While thinking about counting bugs found as a basis of a global statistic, we have then
been pondering what might a local statistic be and whether such a thing would be of any
use. To us, a local statistic would be derived from data gathered only on a small portion of a
larger application, or on a piece of code that synthesizes a small portion of an application.
 One example might be the number of times a specific
compare instruction was reached. This does not take into account the entire application, but
only a portion of it; i.e., a localized portion of the application. Moving on from
this basic example,  we use the notion of ```fuzzing roadblocks``` in the following  discussion.                       

 
Due to this being incomplete work requiring further thought and active investigation,
this is mostly conjectural in nature.

We should recall that a fuzzing roadblock (or speedbump, etc) is typically a "complex sanity check" [TFuzz]  in the code
performed on the input data. It is a few instructions that end with a conditional branch
with the properties that a) the chosen landing branch is dependent on the prior instructions
and b) a fuzzer often produces inputs to take only one of the branches (an uninteresting branch).
An example case is that of some data containing a field that represents a checksum of the
remaining data, as seen in the pseudo-code:


```
   struct s *p = read_from_file();
   unsigned ck = 0;
   unsigned saved_ck = p->checksum_field;
   p->checksum_field = 0;
   ck = calc_crc32(p);
   if (ck != saved_ck) {
      exit(1);
   }
   /* continue */ 
```

So what can occur here with many fuzzers is that they will generate a new
input and not know to recalculate the checksum field, thus resulting in
the exit() branch to be taken the majority of the time. By taking that
one path the majority of the time, it is missing out on fuzzing the code
on the rare-path.  Other examples of roadblocks include:

- Constant multi-byte (magic value) compares
- Data with a length field not matching expected lengths


It should be noted that there are methods for eliminating these roadblocks
by various means. For example, recognition of checksums statically and removing them, 
using magic value table on constant compares, splitting up
multi-byte compares into 8-bit checks to bait the fuzzer [LafIntel]. In the extreme,
there is even T-Fuzz [TFuzz] which will mutate the program to be in an easier to 
fuzz form. But we assume the worst case here; that is, the roadblocks cannot
be removed for some reason. Additionally, while any fuzzer might have a technique
to move past a given roadblock, any fuzzer is extremely unlikely to remove all
roadblocks it comes across.

The initial thinking is that the local statistic would be  related to
how well a fuzzer does on individual roadblocks, or perhaps a series of roadblocks. Note that this is
local because it is only focusing on part of what might make up a larger application. By "how well", 
we mean what is the probability of taking the rare path under a given fuzzer, a given seed, etc. and how
does that evolve over the duration of the fuzzing process. There are a few ways
one could model probability of branch taken at a given conditional branch, whether it be a 
fair coin flip model or some other. We can propose some non-trivial, worst case, branch probability distribution
for a given roadblock and then look at how the fuzzer runs compared with this and with each other.
Note that this is different than looking at something like branch coverage from a code coverage
perspective [Groce]. 

As an aside, one possible benefit in performing this type of  analysis is
that if you understand how a given set of roadblocks impact a fuzzer you wish to use, 
then you can adjust the amount of compute you run in your fuzzing campaign to increase
number of times the rare-branch path is taken over time. For the target program to be
fuzzed, perform a static analysis looking for roadblocks in the code and log them. Using
this data, one could conceivably calculate the cost of those roadblocks in terms of 
failures of executions to take the rare-path for the fuzzer you plan to use. This can be used
to adjust your hardware and distributed fuzzer strategy to increase odds of higher
branch coverage in time. Additionally, if one compares different fuzzers on how they handle
roadblocks, then this static analysis would also help to determine which fuzzer is the best to
use for the target code. Even more, one can imagine a fuzzer that could deploy different methodologies for mutatation
when reaching such roadblocks.

With all these thoughts in mind, we set out to develop a handful of
applications that had the following properties:

- the code would be minimal: code limited to only that which is directly related to a roadblock
- the code would contain a very minimal number of conditional branches: low branch count
- at least one of the conditional branches is part of a roadblock
- logged when reached (or not) the rare-branch

The idea is to focus the tests around a specific roadblock or series of them and so the only code
we are interested in is that which leads to the conditional branch in the roadblocks of interest.
These would be runnable examples of what one might find in a larger application.
Thus, any excess code should be not included that is unrelated. Further, we want to focus on the
conditional branch with the rare path and so we desire a lesser number of such statements to 
increase sensitivity. The need for logging is to track the rare branch hits along with timestamps.

An example might be:

```
int
main(int argc, char **argv)
{
  struct stat sb;
  unsigned char *bdyn;
  unsigned int read_crc = 0;
  unsigned int crc = 0;
  fd = open(argv[1], 'r');
  log_open();
  fstat(fd, &sb);
  bdyn = (unsigned char *)malloc(sb.st_size); // XXX: possible bugs due to no checks below...
  read(fd, &read_crc, sizeof(unsigned int)); 
  read(fd, bdyn, sb.st_size-sizeof(unsigned int));
  crc = calc_crc32(bdyn, sb.st_size-sizeof(unsigned int), 0);
  if (read_crc != crc) {
    return -1;
  }
  log_branch_reached();
  return 0;
}
```

The idea here is to just hammer (repeatedly execute) the roadblocks with a given fuzzer and count
the number of times rare branches are taken versus the more common path. These can be looked at
over time to understand the weights on this coin-flip determining branch selection.
Aside from the single case, we also felt that conceivably series of these roadblocks coule be useful cases to gather
data on. For example, augmenting the example above to include a constant check as well:

```
  int mg = 0;
  read(fd, &mg, sizeof(int));
  if (mg != 0xd34db33f) {
    return -2;
  }
  bdyn = (unsigned char *)malloc(sb.st_size-sizeof(int)); // XXX: clearly some issues on return values :P
  read(fd, &read_crc, sizeof(unsigned int));
  read(fd, bdyn, sb.st_size-sizeof(unsigned int)-sizeof(int));
  crc = calc_crc32(bdyn, sb.st_size-sizeof(unsigned int), 0);
  if (read_crc != crc) {
    return -1;
  }
  log_branch_reached();
```

In the above, a "magic" value is read from the fd and the multi-byte compare occurs
against ```0xd34db33f```. Upon passing that check, the calc_crc32() roadblock is reached.
The aim of this was to investigate the 
conditional rates; further, ordering the checks in both ways to determine if there
was any commutative relationship between roadblocks. 
So we began to develop such test cases:

- 32-bit magic check
- 32-bit magic check, followed by another 32-bit magic check on a different value
- crc32 checksum check
- 32-bit magic check, followed by crc32 checksum check
- crc32 checksum check, followed by 32-bit magic check

For each test case, there is also the question of what seeds to use and so some good
and bad seeds have been developed for these. The good seed simply gets you to the 
desired rare branch path. The bad seeds are slightly more varied -- with, say, a seed 
case for magic value comparisons having a "bad" magic value of 0, another seed with
it set to ~0, etc. 

However, after getting to this point and starting to select fuzzers to use in some initial runs
to exercise the setup, that perhaps these basic tests were
only good enough to test certain classes of fuzzers. Certainly a fuzzer, like qsym [qsymPaper]
[qsym], which uses a solver for when roadblocks are detected, should do well against small test cases 
where there is not a large state space. Further, shouldn't these also be too simple for certain 
ML-based fuzzers? Initial testing with qsym did indicate that this was the case. For this reason,
testing did not continue through to statistically significant numbers of numbers, but halted in
order to rethink things.

This has led us to start to rethink how one might construct such tests to provide reasonable testing 
of roadblock handling across any given fuzzer and whether "any given fuzzer" is a reasonable goal.
It also brings up the question of how to determine
the impact on a fuzzing process given a roadblock existing in shallow waters versus one existing at
a deeper call depth.  It has also led us to ponder other possible local statistics that might be that
could be useful in comparison, such as logging reachability of certain instructions and think as to
whether they have any true use. The hope is that 
some understanding of behavior of a fuzzer on certain small regions of code in an application can
give insight to the global behavior of a fuzzer on the application as a whole.

Unfortunately, the outcome is not some spectacular great new solution. Yet what it does provide is additional 
evidence that the space of different fuzzers/fuzzing techniques is large and diverse enough such that coming
up with metrics for comparison across the entire space is non-trivial. While the proposed localized
statistic still needs some proper investigation, we feel that there are likely other possible
examples of such statistics that could warrant research as well, e.g. loop statistics, resulting in a set of
such that help give finer-grained insight into fuzzer behavior.

### Bibiliography

- [Manes]  V. Man\`{e}s, et al., "The Art, Science, and Engineering of Fuzzing: A Survey", [arXiv preprint](http://arxiv.org/abs/1812.00140)
- [VidCon] N. Silvanovich, "Adventures in Video Conferencing", [Infiltrate 2019](https://infiltratecon.com/schedule/)
- [Hicks] M. Hicks, et al., "Evaluating Fuzz Testing", ACM CCS '18. DOI: [https://doi.org/10.1145/3243734.3243804](https://doi.org/10.1145/3243734.3243804)
- [BöhmeStat] M. Bohme, "Assurance in Software Testing: A Roadmap", [arXiv preprint](https://arxiv.org/pdf/1807.10255.pdf)
- [Berger] E. Berger, et al., "A Checklist Manifesto for Empirical Evaluation: A Preemptive Strike Against a Replication Crisis in Computer Science", [https://www.sigarch.org/a-checklist-manifesto-for-empirical-evaluation-a-preemptive-strike-against-a-replication-crisis-in-computer-science/](https://www.sigarch.org/a-checklist-manifesto-for-empirical-evaluation-a-preemptive-strike-against-a-replication-crisis-in-computer-science/)
- [LafIntel] laf-intel, [https://gitlab.com/laf-intel/laf-llvm-pass](https://gitlab.com/laf-intel/laf-llvm-pass)
- [Groce] A. Groce, et al., "Coverage and Its Discontents", Proceedings of Onward! 2014, DOI: [https://doi.org/10.1145/2661136.2661157](https://doi.org/10.1145/2661136.2661157)
- [LLVMClass] [Branch Probability](http://llvm.org/doxygen/classllvm_1_1BranchProbability.html)
- [AFLFastPaper] M. Böhme, et al.,  "Coverage-based Greybox Fuzzing as Markov Chain", ACM CCS 2016
- [AFLFast] AFLFast GitHub, [Github repo](https://github.com/mboehme/aflfast)
- [TFuzz] H. Ping, et al., "T-Fuzz: fuzzing by program transformation", IEEE S&P 2018
- [qsymPaper] I. Yun, et al., "Qsym : A Practical Concolic Execution Engine Tailored for Hybrid Fuzzing", USENIX Security 2018
- [qsym] QSym Github, [Github repo]https://github.com/sslab-gatech/qsym)

Andrew R. Reiter is a researcher within the Applied Research Group at Veracode. 
Andrew expresses his thanks to Jared Carlson, Valentin Manes, Stefan Nagy, Marcel Bohme, and 
the Veracode research group for reading and reviewing/discussing this document. Their 
comments undoubtedly will help in further exploration of this topic.

Additionally, if interested in fuzzing and statistics, the author also recommends looking at the "When to Stop Fuzzing"
chapter of the "fuzzing book" found
[https://www.fuzzingbook.org/html/WhenToStopFuzzing.html](https://www.fuzzingbook.org/html/WhenToStopFuzzing.html).


