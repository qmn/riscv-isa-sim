require_vector;
for (int i=0; i<VL; i++)
{
  uts[i]->pc = RS1+SIMM;
  uts[i]->utmode = true;
  uts[i]->run = true;
  while (uts[i]->utmode)
    uts[i]->step(100, false); // XXX
}
