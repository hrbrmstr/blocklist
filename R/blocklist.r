S_GET <- purrr::safely(GET)

#' Query <blocklist.de> API for IPs blocked in since a period in time, optionally
#' filtering by service
#'
#' @param since either a UNIX timestamp (e.g. \code{1459736686}), a string in "\code{HH:MM}"
#'        format or a time difference in seconds (e..g \code{3600}). The API will
#'        return all requested IPs logged since that time. Leave \code{NULL} for the
#'        API default.
#' @param service only return addresses for a given service. Default: \code{all} services.
#' @export
#' @examples
#' # defaults
#' get_last_added_ips()
#'
#' # last hour
#' get_last_added_ips(3600)
#'
#' # since 3PM today
#' get_last_added_ips("15:00")
#'
#' # for ssh blocks in the last hour
#' get_last_added_ips(3600, "ssh")
get_last_added_ips <- function(since=NULL,
                               service=c("all", "amavis", "apacheddos", "asterisk",
                                         "badbot", "ftp", "imap", "ircbot",
                                         "mail", "pop3", "regbot", "rfi-attack",
                                         "sasl", "ssh", "w00tw00t", "portflood",
                                         "sql-injection", "webmin", "trigger-spam",
                                         "manuall", "bruteforcelogin")) {

  service <- match.arg(service, c("all","amavis", "apacheddos", "asterisk", "badbot",
                                  "ftp", "imap", "ircbot", "mail", "pop3", "regbot",
                                  "rfi-attack", "sasl", "ssh", "w00tw00t", "portflood",
                                  "sql-injection", "webmin", "trigger-spam", "manuall",
                                  "bruteforcelogin"))

  query <- list(time=since %||% "")

  if (service != "all") { query$service <- service }

  res <- S_GET("http://api.blocklist.de/getlast.php", query=query)

  if (is.null(res$result)) {
    stop("Error querying <blocklist.de> API", call.=FALSE)
  }

  httr::warn_for_status(res$result)

  tmp <- readLines(textConnection(content(res$result, as="text")))

  if (grepl("ERROR", tmp[1])) {
    warning("<blocklist.de> API error (check `since` specification)")
    return(NA)
  }

  tmp[tmp != ""]

}
