rule RulanCampaign_20171010{
  strings:
    $s1 = ".ru/hil"
  condition:
    all of them
}

rule SeamlessCampaign_20171010{
  strings:
    $s1 = "194.58."
    $s2 = ".php"
  condition:
    all of them

}

rule FobosCampaign_20171010{
  meta:
    c1 = "hack "
  strings:
    $r1 = /\/index.php\?[a-z]{2}=\d+$/
  condition:
    all of them

}

rule Rig_zoneid_var_20171010 {
  meta:
    description = "hxxp://deloton.com/afu.php?zoneid=1365143&var=1325797"
  strings:
    $r1 = /\/afu.php\?zoneid=\d+/
    $r2 = /&var=\d+$/
  condition:
    all of them
}

rule Rig_nikt_20171010 {
  meta:
    description = "http://2044494sskdk.tk/nikt/?re=61869771446"
  strings:
    $r1 = /\/\?re=\d+$/
  condition:
    all of them
}

rule Rig_tk_ml_20171010 {
  meta:
    description1 = "http://day0510.ga/"
    description2 = "http://acotan.tk/"
  strings:
    $s1 = /http:\/\/[a-z0-9]{5,10}\.[a-z]{2}\/$/
  condition:
    all of them
}


rule Rig_watch_key_20171010 {
  meta:
    description = "http://www.hicpm5.com/watch?key=e9c0c352fd1f4f9820ae0a9cdc0e0149"
  strings:
    $s1 = "watch?key"
  condition:
    all of them
}

rule Rig_post_20171012 {
  meta:
    description = "http://ponturi.online/post/7/8562"
  strings:
    $r1 = /\/post\/\d+\/\d+$/
  condition:
    all of them
}

rule Rig_script_stamat_20171012 {
  meta:
    description = "http://www.adexchangegate.com/script/wait.php?stamat=m%7C%2C%2CA2MqNhevoGU3BZ9GH0dEdHP3xP.12c%2CHYONwZ-sR5uUqzCsf1a6L05Z_g2AE2W9rH3-TwjmHWg_341sVADLtTE-eJQuRFb-aYrGcOchkj6_nSKFkahgif-ewpchvPGicEHUKes7x6KbhjJ9y5jXeeW4U73FvHmqKE2KQOXWAxcNwVgjmZbMQKOYfPfUjlg2DfbJ4drmfXx9beRd26BEOFVjjjMTdbH_4CzhgFnASrZND0i3EjrHTbkrrsmQYHdUz9PpyqoNrPlPCybHeUSeELvS1u7nSTa6LuG-D_dj_A-l1G7tnao0ZCOeKC3gCtQy4TDWjB-O-FcE58hgbWGFCIm4kOZBFFWiQnVDcQNbf1FhBagMrU9r-wt4iUxtbnPRjAuMUeZ6KbRwJisXdhOB5SSm8xZvHmMa8ffwlFJPDar7Sh_SZEPtjz_oVu2IbVzCZZraYn5B7OrPGX-2RQsk2id9iDFwWe75B_-gP13ytKfEBGnxp-rpeg%2C%2C&brb=0&ttc=cy9pp9y4c"
  strings:
    $s1 = "/script/"
    $s2 = ".php?"
    $d3 = "stamat="
  condition:
    all of them
}




