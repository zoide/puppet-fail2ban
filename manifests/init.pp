# fail2ban puppet module
# it expects $jails to be an array of jails to be enabled
# and $mailto an email address to send notifications to.
# $custom_jails are additional custom jails
class fail2ban (
  $jails          = [],
  $mailto         = "",
  $custom_jails   = "",
  $ignoreip       = "127.0.0.1",
  $action_handler = 'shorewall',
  $ensure         = 'present') {
  package { ["fail2ban"]: ensure => $ensure; }

  package { ["gamin", "iptables"]: }

  if $ensure == 'present' {
    service { "fail2ban":
      ensure => running,
      enable => true;
    }
    $f2b_etc = "/etc/fail2ban"
    $jail_local_d = "${f2b_etc}/jail.local.d"

    File {
      owner   => root,
      group   => root,
      require => Package["fail2ban"],
      notify  => Exec["fail2ban.local-generate"],
    }

    file {
      "${f2b_etc}/filter.d":
        source  => "puppet:///modules/fail2ban/filter.d",
        recurse => true,
        force   => true;

      "${jail_local_d}/00_jail.local":
        mode    => 644,
        content => template("fail2ban/jail.local.erb");

      "${jail_local_d}":
        ensure => "directory",
    }

    exec { "fail2ban.local-generate":
      command     => "cat ${jail_local_d}/* >${f2b_etc}/jail.local",
      refreshonly => true,
      notify      => Service["fail2ban"]
    }

    # munin
    # TODO better way to know if node is including munin class
    if $munin_graphs {
      file {
        "/etc/munin/plugins/all_jails":
          mode    => 755,
          source  => "puppet:///modules/fail2ban/munin-all_jails",
          require => Package[$munin],
          notify  => Service["munin-node"];

        "/etc/munin/plugin-conf.d/all_jails":
          content => "[all_jails]\nuser root",
          require => Package[$munin],
          notify  => Service["munin-node"];
      }
    }
  }

  define jail (
    $ensure    = "present",
    $jail_name = "",
    $enabled   = true,
    $filter    = "",
    $action,
    $mailto    = "",
    $logpath,
    $maxretry  = 5,
    $order     = 99) {
    $jail_name_r = $jail_name ? {
      ""      => $name,
      default => $jail_name,
    }
    $filter_r = $filter ? {
      ""      => $jail_name_r,
      default => $filter,
    }

    file { "${fail2ban::jail_local_d}/${order}-${jail_name_r}":
      ensure  => $ensure,
      content => template("fail2ban/jail.local.snipp.erb"),
      notify  => Exec["fail2ban.local-generate"],
    }
  }
}
